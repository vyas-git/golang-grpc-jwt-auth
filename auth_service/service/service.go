package service

import (
	"auth_service/app"
	"auth_service/config"
	"auth_service/proto"
	"auth_service/storage"
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

//MainServer struct combines Auth and Admin services
type MainServer struct {
	*AuthManager
	*AdminManager
}

//AuthManager contains jwt config, storage and conn to mail queue
type AuthManager struct {
	config    *config.Config
	storage   storage.Storage
	queueConn *nats.EncodedConn
	proto.UnimplementedAuthServer
}

//AdminManager contains channels to store logging connections
type AdminManager struct {
	ctx context.Context
	mu  *sync.RWMutex

	loggingBroadcast chan *proto.Event
	loggingListeners map[int]chan *proto.Event
	proto.UnimplementedAdminServer
}

//newMainServer create new MainServer entity
func newMainServer(ctx context.Context, config *config.Config, db storage.Storage, qCoon *nats.EncodedConn) *MainServer {
	//var logLs []chan *proto.Event
	logLs := make(map[int]chan *proto.Event)
	logB := make(chan *proto.Event)
	return &MainServer{
		&AuthManager{
			config:    config,
			storage:   db,
			queueConn: qCoon,
		},
		&AdminManager{
			mu:               &sync.RWMutex{},
			ctx:              ctx,
			loggingBroadcast: logB,
			loggingListeners: logLs,
		},
	}
}

//StartService start gRPC server
func StartService(ctx context.Context, addr string, config *config.Config, db storage.Storage, qCoon *nats.EncodedConn) error {
	g, ctx := errgroup.WithContext(ctx)
	ms := newMainServer(ctx, config, db, qCoon)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening %s err: %v", addr, err)
	}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(ms.unaryInterceptor),
		grpc.StreamInterceptor(ms.streamInterceptor),
	)

	g.Go(func() error {
		proto.RegisterAuthServer(server, ms.AuthManager)
		proto.RegisterAdminServer(server, ms.AdminManager)
		fmt.Println("starting server at " + addr)
		return server.Serve(lis)
	})

	g.Go(func() error {
		for {
			select {
			case event := <-ms.loggingBroadcast:
				ms.mu.Lock()
				for _, ch := range ms.loggingListeners {
					ch <- event
				}
				ms.mu.Unlock()
			case <-ctx.Done():
				return nil
			}
		}
	})

	go func() {
		select {
		case <-ctx.Done():
			break
		}
		if server != nil {
			server.GracefulStop()
		}
	}()
	return nil
}

func (am *AuthManager) Register(ctx context.Context, data *proto.RegisterUserData) (*proto.Tokens, error) {
	if _, err := am.storage.GetUserByLogin(data.Email); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "user with such login already exist")
	}

	user := app.User{
		Fname:        data.Fname,
		Lname:        data.Lname,
		Email:        data.Email,
		PasswordHash: data.Password,
		Organisation: data.Organisation,
	}
	if err := user.HashPassword(); err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("hashing password err: %v", err))
	}

	if err := am.storage.CreateUser(&user); err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("create user err: %v", err))
	}

	tokens, err := user.RefreshTokens(am.config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("refresh user tokens err: %v", err))
	}
	if data.Email != "" {
		m := struct {
			Email string
			Title string
			Body  string
		}{
			Email: data.Email,
			Title: "Thanks for registration",
			Body:  fmt.Sprintf(`Greetings from Sandata Sytems. You have successfully registered with us and your credentials login: %s, password: %s to log in!`, data.Email, data.Password),
		}
		if err := am.queueConn.Publish("emails", m); err != nil {
			log.Printf("pushing msg to queue err: %v\n", err)
		}
	}
	return tokens, nil
}

func (am *AuthManager) Login(ctx context.Context, data *proto.ReqUserData) (*proto.Tokens, error) {
	user, err := am.storage.GetUserByLogin(data.Email)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}
	if !user.PasswordIsValid(data.Password) {
		return nil, status.Errorf(codes.Unauthenticated, "invalid password")
	}

	tokens, err := user.RefreshTokens(am.config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("refresh user tokens err: %v", err))
	}
	return tokens, nil
}

func (am *AuthManager) Profile(ctx context.Context, req *proto.AccessToken) (*proto.RespUserData, error) {
	userID, err := app.UserIDFromToken(req.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	user, err := am.storage.GetUserByID(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	return &proto.RespUserData{
		Id:    int64(user.ID),
		Email: user.Email,
		Admin: user.Admin,
	}, nil
}
func (am *AuthManager) ProfileDelete(ctx context.Context, req *proto.AccessToken) (*proto.RespDeleteUser, error) {
	userID, err := app.UserIDFromToken(req.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	msg, err := am.storage.DeleteUserByID(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	return &proto.RespDeleteUser{
		Status: msg,
	}, nil
}
func (am *AuthManager) ProfileUpdate(ctx context.Context, req *proto.UpdateUserData) (*proto.RegisterUserData, error) {
	userId, err := app.UserIDFromToken(req.AccessToken.AccessToken, am.config.AccessKey)

	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	user_update := app.User{
		Fname:        req.Fname,
		Lname:        req.Lname,
		Organisation: req.Organisation,
	}
	user, err := am.storage.PutUserByID(userId, &user_update)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	return &proto.RegisterUserData{
		Fname:        user.Fname,
		Lname:        user.Lname,
		Organisation: user.Organisation,
	}, nil
}

func (am *AuthManager) CreateSecret(ctx context.Context, req *proto.AccessToken) (*proto.Secret, error) {
	userID, err := app.UserIDFromToken(req.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	user, err := am.storage.GetUserByID(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	key := []byte(am.config.SecretKey)
	plaintext := []byte(user.Email + "," + user.Organisation)
	encrypted_key, err := app.EncryptSecret(key, plaintext)
	encrypted_text := fmt.Sprintf("%0x\n", encrypted_key)
	new_secret := app.Secret{
		SecretKey: string(encrypted_text),
	}
	data, err := am.storage.NewSecretKey(userID, &new_secret)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	return &proto.Secret{
		SecretId:   int32(data.SecretId),
		SecretKey:  data.SecretKey,
		ExpireDate: data.ExpireDate,
		CreatedAt:  data.CreatedAt,
	}, nil
}

func (am *AuthManager) GetSecret(ctx context.Context, req *proto.ReqGetSecretExpire) (*proto.RespGetSecretExpire, error) {
	_, err := app.UserIDFromToken(req.AccessToken.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	data, err := am.storage.GetSecretExpired(uint(req.SecretId))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}
	return &proto.RespGetSecretExpire{
		Status: data,
	}, nil
}
func (am *AuthManager) GetSecrets(ctx context.Context, req *proto.AccessToken) (*proto.Secrets, error) {
	userID, err := app.UserIDFromToken(req.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}

	data, err := am.storage.GetSecrets(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get secrets err: %v", err))
	}
	var secrets []*proto.Secret
	for _, val := range *data {
		var secret = &proto.Secret{
			SecretId:   int32(val.SecretId),
			SecretKey:  val.SecretKey,
			ExpireDate: val.ExpireDate,
			CreatedAt:  val.CreatedAt,
		}
		secrets = append(secrets, secret)
	}
	return &proto.Secrets{
		Secrets: secrets,
	}, nil
}

func (am *AuthManager) DeleteSecret(ctx context.Context, req *proto.ReqDeleteSecret) (*proto.Secrets, error) {
	userID, err := app.UserIDFromToken(req.AccessToken.AccessToken, am.config.AccessKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	data, err := am.storage.DeleteSecret(uint(req.SecretId), userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("delete secrets err: %v", err))
	}
	var secrets []*proto.Secret
	for _, val := range *data {
		var secret = &proto.Secret{
			SecretId:   int32(val.SecretId),
			SecretKey:  val.SecretKey,
			ExpireDate: val.ExpireDate,
			CreatedAt:  val.CreatedAt,
		}
		secrets = append(secrets, secret)
	}
	return &proto.Secrets{
		Secrets: secrets,
	}, nil

}

func (am *AuthManager) RefreshTokens(ctx context.Context, req *proto.RefreshToken) (*proto.Tokens, error) {
	userID, err := app.UserIDFromToken(req.RefreshToken, am.config.RefreshKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("extracting user id from token err: %v", err))
	}
	user, err := am.storage.GetUserByID(userID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, fmt.Sprintf("get user err: %v", err))
	}

	tokens, err := user.RefreshTokens(am.config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("refresh user tokens err: %v", err))
	}

	return tokens, nil
}
func (am *AuthManager) mustEmbedUnimplementedAuthServer() {
	fmt.Println("Implemeneted")
}

func (am *AdminManager) Logging(in *proto.Nothing, alSrv proto.Admin_LoggingServer) error {
	id, ch := am.addLogListenersCh()
	for {
		select {
		case event := <-ch:
			if err := alSrv.Send(event); err != nil {
				log.Printf("sending to client err: %v\n", err)
				log.Println("deleting channel from pool")
				am.deleteLogListenersCh(id)
			}
		case <-am.ctx.Done():
			return nil
		}
	}
}
func (am *AdminManager) mustEmbedUnimplementedAdminServer() {
	fmt.Println("Implemeneted")

}

func (am *AdminManager) addLogListenersCh() (int, chan *proto.Event) {
	id, ch := randInt(), make(chan *proto.Event)
	am.mu.Lock()
	defer am.mu.Unlock()
	am.loggingListeners[id] = ch
	return id, ch
}

func (am *AdminManager) deleteLogListenersCh(id int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.loggingListeners, id)
}

func (ms *MainServer) unaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	reply, err := handler(ctx, req)

	if err := ms.pushEvent(ctx, info.FullMethod, err); err != nil {
		log.Printf("can`t push event: %v", err)
	}

	return reply, err
}

func (ms *MainServer) streamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	//get "key" from client req context
	key, err := ms.keyFromCtx(ss.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, fmt.Sprintf("getting key from ctx: %v", err))
	}

	//simple auth
	validKey := "admin_key"
	if key != validKey {
		return status.Errorf(codes.Unauthenticated, fmt.Sprintf("invalid admin key"))
	}

	return handler(srv, ss)
}

func (ms *MainServer) keyFromCtx(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata in incoming context")
	}
	mdValues := md.Get("key")
	if len(mdValues) < 1 {
		return "", fmt.Errorf("no key in context metadata")
	}
	return mdValues[0], nil
}

func (ms *MainServer) pushEvent(ctx context.Context, method string, err error) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("can`t get peer from context")
	}

	var code = codes.OK
	var msg string
	if err != nil {
		if st, ok := status.FromError(err); ok {
			code = st.Code()
			msg = st.Message()
		}
	}

	ms.loggingBroadcast <- &proto.Event{
		Host:      p.Addr.String(),
		Method:    method,
		Code:      int32(code),
		Err:       msg,
		Timestamp: time.Now().Unix(),
	}
	return nil
}

func randInt() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Int()
}
