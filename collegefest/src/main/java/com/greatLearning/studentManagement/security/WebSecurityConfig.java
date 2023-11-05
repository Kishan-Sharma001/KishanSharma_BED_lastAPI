package com.greatLearning.studentManagement.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.greatLearning.studentManagement.service.UserDetailsServiceImpl;




@Configuration
public class WebSecurityConfig implements WebMvcConfigurer{

	 @Bean
	    public UserDetailsService userDetailsService() {
	        return new UserDetailsServiceImpl();
	    }
	     
	    @Bean
	    public BCryptPasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	     
	    @Bean
	    public DaoAuthenticationProvider authenticationProvider() {
	        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	        authProvider.setUserDetailsService(userDetailsService());
	        authProvider.setPasswordEncoder(passwordEncoder());
	         
	        return authProvider;
	    }
	 
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider());
	    }
	 
	    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {

	           
	            
	            http.csrf(csrf -> csrf.disable()).authorizeHttpRequests((authorize) -> authorize
	    				
	    				.requestMatchers(new AntPathRequestMatcher("/student/showFormForUpdate","/student/delete")).hasAuthority("ADMIN").anyRequest().authenticated())
	    				.formLogin(form -> form.loginPage("/login").defaultSuccessUrl("/student/lists")
	    						.loginProcessingUrl("/login").permitAll())
	    				.logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/login")).permitAll());
	    		return http.build();
	    }
	  

}
