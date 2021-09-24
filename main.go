package main

/* You have two functions: one prints 1-100 all even numbers, another prints 1-100 all odd numbers.

Write a program to synchronize these two functions so that final output should be 1-100 in series.
*/


func even() {
	
	for i := 0; i < 100; i++ {
	even := make(ch int)
	 if i%2 == 0 {
		 ch <- i
	 }
	}
}

func odd() {
	for i := 0; i < 100; i++ {

	}
}

func main() {
	go even()

	go odd()

}
