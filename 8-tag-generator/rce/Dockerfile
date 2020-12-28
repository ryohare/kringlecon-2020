FROM ubuntu:latest

apt update
apt install imagemagick vim socat net-tools ruby -y

COPY app /app

WORKDIR /app

RUN gem install bundle
RUN /usr/lib/ruby/gems/2.7.0/gems/bundler-2.1.2/libexec/bundle

ENTRYPOINT '/usr/local/bin/rackup'] 
