FROM debian

LABEL maintainer "Claudio Guarnieri"

EXPOSE 9222

RUN apt-get update
RUN apt-get -qqy install wget ca-certificates apt-transport-https gnupg2 software-properties-common tor

RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN apt-add-repository "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main"

RUN apt-get update
RUN apt-get -qqy install google-chrome-stable

#RUN groupadd -g 999 phished && useradd -r -u 999 -g phished phished
RUN mkdir /data
#RUN chown phished:phished /data

ADD start.sh /usr/bin/
RUN ["chmod", "+x", "/usr/bin/start.sh"]

ENV HOME=/data DEBUG_ADDRESS=0.0.0.0 DEBUG_PORT=9222

CMD ["/usr/bin/start.sh"]
