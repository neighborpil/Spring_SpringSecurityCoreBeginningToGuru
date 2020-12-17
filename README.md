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
   
