FROM adoptopenjdk:11-jre-hotspot as builder
MAINTAINER epam.com
VOLUME /tmp
ARG JAR_FILE=/build/libs/*.jar
COPY ${JAR_FILE} auth-service.jar
ENTRYPOINT ["java","-jar","/auth-service.jar"]