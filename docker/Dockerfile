# Dockerfile for universalresolver/driver-did-dns

FROM maven:3-jdk-11 AS build
MAINTAINER Markus Sabadello <markus@danubetech.com>

# build driver-did-dns

ADD . /opt/driver-did-dns
RUN cd /opt/driver-did-dns && mvn clean install package -P war -N -DskipTests

FROM jetty:9.4-jre11
MAINTAINER Markus Sabadello <markus@danubetech.com>

USER jetty

# variables

ENV uniresolver_driver_did_dns_dnsServers=
ENV uniresolver_driver_did_dns_didKeyResolver=https://dev.uniresolver.io/1.0/

# copy from build stage

COPY --from=build --chown=jetty /opt/driver-did-dns/target/*.war /var/lib/jetty/webapps/ROOT.war

# done

EXPOSE 8080
CMD java -Djetty.http.port=8080 -jar /usr/local/jetty/start.jar
