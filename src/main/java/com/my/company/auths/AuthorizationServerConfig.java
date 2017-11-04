package com.my.company.auths;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
    private AuthenticationManager authenticationManager;
	
	@Autowired
	private Environment environment;
	
	@Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.tokenStore(tokenStore())
			.tokenEnhancer(jwtTokenEnhancer())
				.authenticationManager(authenticationManager).pathMapping("oauth/check_token", "oauth/validate");
    }
	
	@Override	
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
			clients.inMemory()
		        .withClient("usemyname")
		        .secret("mypassword")
		        .scopes("read", "write") 
		        .authorities("ROLE_READ","ROLE_USER")
		        .authorizedGrantTypes("client_credentials", "refresh_token", "password")
		        .accessTokenValiditySeconds(30)
			
			.and()
	        .withClient("adminuser")
	        .secret("adminpassword")
	        .scopes("read", "write") 
	        .authorities("ROLE_READ","ROLE_USER", "ROLE_ADMIN", "reader")
	        .authorizedGrantTypes("client_credentials")
	        .accessTokenValiditySeconds(600);
			
			
	 }
	
	
	@Bean
	public TokenStore tokenStore() {
		//return new InMemoryTokenStore();
		return new JwtTokenStore(jwtTokenEnhancer());
	}
	
	@Bean
	protected JwtAccessTokenConverter jwtTokenEnhancer() {
		String pwd = environment.getProperty("keystore.password");
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"),
				pwd.toCharArray());
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
		return converter;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permitAll()")
	    		.checkTokenAccess("isAuthenticated()");
		
		
	}
	
	

}
