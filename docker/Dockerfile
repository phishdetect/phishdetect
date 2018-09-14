FROM debian

LABEL maintainer "Claudio Guarnieri"

EXPOSE 9222

RUN apt-get update
RUN apt-get -qqy install wget ca-certificates apt-transport-https gnupg2 software-properties-common tor

RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN apt-add-repository "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main"

RUN apt-get update
RUN apt-get -qqy install google-chrome-stable

RUN groupadd -r chrome && useradd -r -g chrome -G audio,video chrome \
	&& mkdir -p /home/chrome && chown -R chrome:chrome /home/chrome

ADD start.sh /usr/local/bin/
RUN ["chmod", "+x", "/usr/local/bin/start.sh"]

USER chrome

ENV DEBUG_ADDRESS=0.0.0.0 DEBUG_PORT=9222

CMD ["/usr/local/bin/start.sh"]
