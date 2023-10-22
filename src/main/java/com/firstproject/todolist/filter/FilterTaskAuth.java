package com.firstproject.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.firstproject.todolist.controller.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       
            var servletPath = request.getServletPath();
            if (servletPath.startsWith("/tasks/")){

                 //Pegar a autentificacao (user and password)
            var authorization = request.getHeader("Authorization");
            
            var authEncoded = authorization.substring("Basic".length()).trim();
           
            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
            
            var authString = new String(authDecoded);

            String[] credentials =authString.split(":");
            String username = credentials[0];
            String password = credentials[1];
            
            //Validar o Usuario
            var user = this.userRepository.findByUsername(username);
            if (user == null){
                response.sendError(401);
            } else {
                //Validar password
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(),user.getPassword());
                if(passwordVerify.verified){
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                }else{
                    response.sendError(401);
                }

            }

            }else {
                 filterChain.doFilter(request, response);   
            }
            
       
       
       
    }

   
    
}
