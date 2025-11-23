# 베이스 이미지로 Java 21 JDK가 설치된 가벼운(alpine) 리눅스 사용
FROM eclipse-temurin:21-jdk-alpine
# 컨테이너 안에서 작업 디렉토리를 /app으로 설정
WORKDIR /app
# 로컬 target 폴더의 *-SNAPSHOT.jar 파일을 컨테이너 /app 폴더에 app.jar로 복사
COPY target/*SNAPSHOT.jar app.jar
# 컨테이너 시작 시 실행할 명령 지정
# 여기서는 java -jar app.jar 명령으로 JAR 파일 실행
ENTRYPOINT ["java","-jar","app.jar"]