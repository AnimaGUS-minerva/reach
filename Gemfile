source 'https://rubygems.org'

#gem 'bundler', '>= 2.6.8'

# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem 'rails', "~> 6.0.0"
gem "actionpack"

# restrictions due to CVEs
gem "rack", ">= 2.2.3.1"
gem "activesupport", ">= 6.0.0"
gem "json", ">= 2.3.0"
gem "tzinfo", ">= 1.2.10"

gem "websocket-extensions", ">= 0.1.5"

gem 'ecdsa',   :git => 'https://github.com/AnimaGUS-minerva/ruby_ecdsa.git', :branch => 'ecdsa_interface_openssl'

#gem 'openssl'
gem 'openssl', :path => "../minerva/ruby3-openssl"

#gem 'chariwt', :path => '../chariwt'
gem 'chariwt', :git => 'https://github.com/AnimaGUS-minerva/ChariWTs.git', :branch => 'v0.11.0'

gem 'jwt'

gem 'celluloid', "~> 0.17.0"
#gem 'celluloid-io', :path => '../minerva/celluloid-io'
gem 'celluloid-io', :git => 'https://github.com/AnimaGUS-minerva/celluloid-io.git', :submodules => true, :branch => '0.17-dtls'

# Use Puma as the app server
#gem 'puma', '~> 3.0'

#gem 'coap', :path => '../minerva/coap'
gem 'coap', :git => 'https://github.com/AnimaGUS-minerva/coap.git', :branch => 'dtls-client'
gem 'cbor'
gem 'cbor-diag'

# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem 'jbuilder', '~> 2.5'

# IP address management for use in ANIMA ACP
gem 'ipaddress', :git => 'https://github.com/mcr/ipaddress.git', :tag => 'v0.9.0mcr'

# Use Capistrano for deployment
# gem 'capistrano-rails', group: :development

# for decoding MIME content types.
gem 'mail'

gem 'byebug'

group :development do
  # Spring speeds up development by keeping your application running in the background. Read more: https://github.com/rails/spring
  gem 'spring'
  gem 'spring-watcher-listen', '~> 2.0.0'
  gem 'webmock'

  gem 'sprockets', "~> 3.7.2"
end

