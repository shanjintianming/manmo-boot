package com.cloud.user.Controller;

import java.util.Optional;

import com.cloud.user.vo.User;

public class UserController {

	public static void main(String[] args) {
		Optional<User> user = Optional.empty();
		
		user.ifPresentOrElse(System.out::println, System.out::println);
	}
	
}
