package cn.leeshuhao.saml.config;

import cn.leeshuhao.saml.provider.ResourceMetadataProvider;
import cn.leeshuhao.saml.properties.SAMLProperties;
import cn.leeshuhao.saml.constant.SAMLConstant;
import cn.leeshuhao.saml.context.ApplicationContextHolder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.saml.util.SAMLUtil.isDateTimeSkewValid;

/**
 * <p>SAML Configuration</p>
 *
 * @author MrLee
 */
@Configuration
@ConditionalOnBean(SAMLProperties.class)
public class SAMLConfiguration extends WebSecurityConfigurerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(SAMLConfiguration.class);

    private SAMLProperties samlProperties;

    private SAMLUserDetailsService samlUserDetailsService;

    private Environment environment;

    public SAMLConfiguration(SAMLProperties samlProperties, SAMLUserDetailsService samlUserDetailsService, Environment environment) {
        this.samlProperties = samlProperties;
        this.samlUserDetailsService = samlUserDetailsService;
        this.environment = environment;
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    @Bean
    public SAMLContextProviderLB contextProvider() {
        URI uri = URI.create(samlProperties.getEntityBaseUrl());
        SAMLContextProviderLB samlContextProviderLB = new SAMLContextProviderLB();
        samlContextProviderLB.setScheme(uri.getScheme());
        samlContextProviderLB.setServerName(uri.getHost());
        samlContextProviderLB.setContextPath(environment.getProperty("server.servlet.context-path"));
        samlContextProviderLB.setStorageFactory(new EmptyStorageFactory());
        return samlContextProviderLB;
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean("samlEntryPoint")
    public SAMLEntryPoint samlEntryPoint(WebSSOProfileOptions webSSOProfileOptions) {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        return samlEntryPoint;
    }

    @Bean
    public FilterChainProxy samlFilter(@Qualifier("samlWebSSOProcessingFilter") SAMLProcessingFilter samlWebSSOProcessingFilter,
                                       @Qualifier("samlWebSSOHoKProcessingFilter") SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter,
                                       @Qualifier("samlDiscovery") SAMLDiscovery samlDiscovery,
                                       @Qualifier("samlEntryPoint") SAMLEntryPoint samlEntryPoint,
                                       @Qualifier("samlLogoutFilter") SAMLLogoutFilter samlLogoutFilter,
                                       @Qualifier("samlLogoutProcessingFilter") SAMLLogoutProcessingFilter samlLogoutProcessingFilter,
                                       @Qualifier("metadataDisplayFilter") MetadataDisplayFilter metadataDisplayFilter
    ) {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login"),
                samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(samlProperties.getSsoUrl(), HttpMethod.POST.name()),
                samlWebSSOProcessingFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/HoKSSO"),
                samlWebSSOHoKProcessingFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery"),
                samlDiscovery));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout"),
                samlLogoutFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout"),
                samlLogoutProcessingFilter));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata"),
                metadataDisplayFilter));
        return new FilterChainProxy(chains);
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        WebSSOProfileConsumerImpl webSSOProfileConsumerImpl = new WebSSOProfileConsumerImpl();
        webSSOProfileConsumerImpl.setMaxAuthenticationAge(24*3600*60);//1天
        return webSSOProfileConsumerImpl;
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public SingleLogoutProfile logoutProfile() {
        return new SingleLogoutProfileImpl();
    }

    @Bean("samlWebSSOProcessingFilter")
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        samlWebSSOProcessingFilter.setFilterProcessesUrl(samlProperties.getSsoUrl());
        return samlWebSSOProcessingFilter;
    }

    @Bean("samlWebSSOHoKProcessingFilter")
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean("samlDiscovery")
    public SAMLDiscovery samlDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        return idpDiscovery;
    }

    @Bean("metadataDisplayFilter")
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl(samlProperties.getEntityBaseUrl() + environment.getProperty("server.servlet.context-path") + SAMLConstant.CONFIRM_URL);
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl(samlProperties.getEntityBaseUrl() + environment.getProperty("server.servlet.context-path") + SAMLConstant.CONFIRM_URL);
        return failureHandler;
    }

    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl(SAMLConstant.CONFIRM_URL);
        return successLogoutHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    @Bean("samlLogoutProcessingFilter")
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        SAMLLogoutProcessingFilter samlLogoutProcessingFilter = new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
        return samlLogoutProcessingFilter;
    }

    @Bean("samlLogoutFilter")
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter(MetadataGenerator metadataGenerator) {
        return new MetadataGeneratorFilter(metadataGenerator);
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        return extendedMetadata;
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(samlProperties.getEntityId());
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        metadataGenerator.setEntityBaseURL(samlProperties.getEntityBaseUrl() + environment.getProperty("server.servlet.context-path"));
        return metadataGenerator;
    }

    @Bean
    public ExtendedMetadataDelegate oktaExtendedMetadataProvider() {
        DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();
        Resource resource = defaultResourceLoader.getResource(samlProperties.getIdpPath());
        ResourceMetadataProvider provider = new ResourceMetadataProvider(resource);
        provider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(provider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(true);
        return extendedMetadataDelegate;
    }

    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource(samlProperties.getJksPath());
        Map<String, String> passwords = new HashMap<>();
        passwords.put(samlProperties.getPrivateKeyName(), samlProperties.getPrivateKeyPass());
        JKSKeyManager jksKeyManager = new JKSKeyManager(storeFile, samlProperties.getStorePass(), passwords, samlProperties.getPrivateKeyName());
        return jksKeyManager;
    }

    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(oktaExtendedMetadataProvider());
        CachingMetadataManager metadataManager = new CachingMetadataManager(providers);
        return metadataManager;
    }

    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), VelocityFactory.getEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public SAMLProcessorImpl processor() {
        ArrayList<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        return new SAMLProcessorImpl(bindings);
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(samlUserDetailsService);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        MetadataGeneratorFilter metadataGeneratorFilter = ApplicationContextHolder.getApplicationContext().getBean(MetadataGeneratorFilter.class);
        SAMLEntryPoint samlEntryPoint = ApplicationContextHolder.getApplicationContext().getBean(SAMLEntryPoint.class);
        FilterChainProxy filterChainProxy = ApplicationContextHolder.getApplicationContext().getBean(FilterChainProxy.class);

        http
                .headers().frameOptions().disable().and()
                .csrf().disable()
                .authorizeRequests().anyRequest().permitAll().and()
                .httpBasic().authenticationEntryPoint(samlEntryPoint).and()
                .addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class)
                .addFilterAfter(filterChainProxy, BasicAuthenticationFilter.class)
                .antMatcher("/saml/**");
    }
}