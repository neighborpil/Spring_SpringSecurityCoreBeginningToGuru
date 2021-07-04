# Spring_SpringSecurityCoreBeginningToGuru
example code of online course


# XSS(Cross-site Scripting Worm)
 - 글을 작성할 때에 javascript코드를 심어서 그 페이지에 접속하는 사람의 컴퓨터에서 실행되게 할 수 있음
 - 엄청 빠르게 퍼짐
 - 서버에서 텍스트를 인코딩 하거나 sanitizing 하지 않아서 발생하는 문제
 - 유저가 유저 페이지에 자바스크립트 텍스트를 적을 수 있고, 이 자바스크립트 코드가 실행되어 발생하는 문제
 - 예방책
  + 유저가 입력한 텍스트에서 자바스크립트 문자는 삭제되어야 한다
  + 특수 문자는 HTML Encoded 해야 한다
  + Header 'X-XXS-Protection'은 '1; mode=block'으로 설정되어야 한다
    (브라우저에게 XXS코드가 발견되면 블록하라는 내용이다)
# CSRF(Cross-Site Request Forgery)
 - 유저가 권한이 있는 것처럼 변경하여 request를 보내어 권한이 없는 영역에 접근하는 것
 - 세션 쿠키를 변조하여 요청을 보내기 때문에 정상적인 사용자인지 구별이 불가능
 - 예방책
  + 요청을 보낼 때에 랜덤한 CSRF토큰을 가지고 있어야 한다
  + CRSF 토큰은 HTTP Request에 포함되어야 한다
   - 쿠키에 저장하면 안된다
   - HTTP Headers 또는 Hidden Form Fields에 포함되어야 한다
 - 언제 사용하나?
  + 브라우저를 사용하는 경우에만
   - HTML 또는 Single page apps(Angular, React)등을 사용할 때에
  + 브라우저를 사용하지 않는 경우에는 CSRF를 disable한다
   - programatic clients like Spring RestTemplate or WebClient
   
# 웹에는 2가지 환경이 있다
 - 하나는 브라우저를 통하는것. 한번 로그인하면 세션이 유지된다
 - 하나는 Resttful API에 접속하는 것. 접속 할 때마다 인증이 필요하다
 

https://www.base64encode.org/
   
#### JPA 테스트 방법  
 - @WebMvcTest에서는 JPA테스트 안됨
 - @SpringBootTest로 클래스 어노테이션을 바꿔줘야 함
```
//@WebMvcTest
@SpringBootTest
public class BeerRestControllerIT extends BaseIT {
```

### Roles VS Authorities
 - Role은 일반적으로 Authorities의 그룹이다
 - Role은 반드시 "ROLE_"를 접두어로 가진다
 - TDD : BeerRestControllerIT.java
```
http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll() //do not use in production!
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll()
                            .mvcMatchers("/brewery/breweries/**")
                                .hasAnyRole("ADMIN", "CUSTOMER")
                            .mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries")
                                .hasAnyRole("ADMIN", "CUSTOMER");
                } )
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic()
                .and().csrf().disable();

```
 
### Method에 Security 적용하는 법
 1. SecurityConfig 헤더쪽에 어노테이션 설정 해준다
```
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
```
 2. 메서드헤더에 어노테이션 설정 해준다
```
    @Secured({"ROLE_ADMIN", "ROLE_CUSTOMER"})
    @GetMapping
    public String processFindFormReturnMany(Customer customer, BindingResult result, Model model){
```
 3. 테스트 케이스 : /methodSecurity폴더 참조


### Synthex별로 권한 주는 방법
 - 동일한 주소(/new)라도 Get, Post방식이 다를 수 있다
 - Post에만 권한을 주는 방법이다
 - Spring5에서부터 된다
 1. SecurityConfig 헤더쪽에 어노테이션 설정 해준다
```
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
```
 2. 메서드헤더에 어노테이션 설정 해준다
```
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/new")
    public String processCreationForm(Customer customer) {
```
 3. 테스트 케이스 : /syntexSecurity폴더 참조


### User - Role - Authority 권한 설정
 - domain 설정: /userRoleAuthority/domain 폴더 참조
 - 


## @PreAuthorize()
 - 각 메소드마다 실행 권한을 설정 할 수 있다
 - @Configuration SecurityConfig 클래스에서 주소에 따른 권한을 설정 할 수 있지만,
   프로그램이 복잡해지면, 권한설정이 어렵고 에러를 일으키기 쉽다
 - @PreAuthorize를 사용하면 각 메소드에 설정하기 때문에 직관적이고 유지보수 하기 쉽다
 - 예제파일 : /preAuthorize폴더 참조
```
    @PreAuthorize("hasAuthority('beer.read')")
    @GetMapping(path = {"beerUpc/{upc}"}, produces = { "application/json" })
    public ResponseEntity<BeerDto> getBeerByUpc(@PathVariable("upc") String upc){
```

## Custom Authorization Annotation
 - @interface를 정의함으로써 권한을 설정 할 수 있다
 - 훨씬 깔끔해진다
 - 정의
 - customAuthorizationAnnotation 폴더 참조
```
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasRole('beer.create')")
public @interface BeerCreatePermission {
}
```
 - 사용
```
//    @PreAuthorize("hasAuthority('beer.delete')")
    @BeerDeletePermission
    @DeleteMapping({"beer/{beerId}"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteBeer(@PathVariable("beerId") UUID beerId){
```

## Multi-tenancy Security
![image](https://user-images.githubusercontent.com/22423285/121757321-239d3d00-cb58-11eb-80ad-24133f4acc30.png)
![image](https://user-images.githubusercontent.com/22423285/121757644-349a7e00-cb59-11eb-952f-28e83b034517.png)

![image](https://user-images.githubusercontent.com/22423285/121757492-b211be80-cb58-11eb-8b0e-2700111d9a7e.png)


#### ※ SPeL : Spring Expression Language


## Customer User 만들기
 - implements UserDetails, CredentialsContainer 
 - serCustomerSetting 폴더 참조
 - 필요한 항목 오버라이드
```

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.enabled;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Builder.Default
    private Boolean accountNonExpired = true;

    @Builder.Default
    private Boolean accountNonLocked = true;

    @Builder.Default
    private Boolean credentialsNonExpired = true;

    @Builder.Default
    private Boolean enabled = true;

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
```
 - lazyloading때문에 Fetch type을 EAGER로 해준다
```
    @Singular
    @ManyToMany(cascade = {CascadeType.MERGE, CascadeType.PERSIST}, fetch = FetchType.EAGER)
    @JoinTable(name = "user_role",
        joinColumns = {@JoinColumn(name = "USER_ID", referencedColumnName = "ID")},
        inverseJoinColumns = {@JoinColumn(name = "ROLE_ID", referencedColumnName = "ID")})
    private Set<Role> roles;
    
    @ManyToOne(fetch = FetchType.EAGER)
    private Customer customer;
```

## Multi-tenancy Security TDD for spring security
 - BeerOrderControllerTest폴더 참조

## Custom Authentication Manager
 - 클래스 생성
```
package guru.sfg.brewery.security;

import guru.sfg.brewery.domain.security.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Slf4j
public class BeerOrderAuthenticationManager {

    public boolean customerIdMatches(Authentication authentication, UUID customerId) {

        User authenticationUser = (User) authentication.getPrincipal();

        log.debug("Auth User Customer Id: " + authenticationUser.getCustomer().getId() + " Customer Id:" + customerId);

        return authenticationUser.getCustomer().getId().equals(customerId);

    }
}
```
 - 적용
```
    @PreAuthorize("hasAuthority('order.read') OR " +
            "hasAuthroity('customer.order.read') AND " +
            "@BeerOrderAuthenticationManager.customerIdMatches(authentication, #customerId)")
    @GetMapping("orders")
    public BeerOrderPagedList listOrders(@PathVariable("customerId") UUID customerId,
                                         @RequestParam(value = "pageNumber", required = false) Integer pageNumber,
                                         @RequestParam(value = "pageSize", required = false) Integer pageSize){

        if (pageNumber == null || pageNumber < 0){
            pageNumber = DEFAULT_PAGE_NUMBER;
        }

        if (pageSize == null || pageSize < 1) {
            pageSize = DEFAULT_PAGE_SIZE;
        }

        return beerOrderService.listOrders(customerId, PageRequest.of(pageNumber, pageSize));
    }
```
 - 테스트
```

    @Transactional
    @Test
    void getByOrderIdNotAuth() throws Exception {
        BeerOrder beerOrder  = stPeteCustomer.getBeerOrders().stream().findFirst().orElseThrow();

        mockMvc.perform(get(API_ROOT + stPeteCustomer.getId() + "/orders/" + beerOrder.getId()))
                .andExpect(status().isUnauthorized());
    }

    @Transactional
    @WithUserDetails("spring")
     @Test
    void getByOrderIdADMIN() throws Exception {
        BeerOrder beerOrder  = stPeteCustomer.getBeerOrders().stream().findFirst().orElseThrow();

        mockMvc.perform(get(API_ROOT + stPeteCustomer.getId() + "/orders/" + beerOrder.getId()))
                .andExpect(status().is2xxSuccessful());
    }

    @Transactional
    @WithUserDetails(DefaultBreweryLoader.STPETE_USER)
     @Test
    void getByOrderIdCustomerAuth() throws Exception {
        BeerOrder beerOrder  = stPeteCustomer.getBeerOrders().stream().findFirst().orElseThrow();

        mockMvc.perform(get(API_ROOT + stPeteCustomer.getId() + "/orders/" + beerOrder.getId()))
                .andExpect(status().is2xxSuccessful());
    }


    @Transactional
    @WithUserDetails(DefaultBreweryLoader.DUNEDIN_USER)
     @Test
    void getByOrderIdCustomerNOTAuth() throws Exception {
        BeerOrder beerOrder  = stPeteCustomer.getBeerOrders().stream().findFirst().orElseThrow();

        mockMvc.perform(get(API_ROOT + stPeteCustomer.getId() + "/orders/" + beerOrder.getId()))
                .andExpect(status().isForbidden());
    }

```
