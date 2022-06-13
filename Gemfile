source 'https://rubygems.org'

git_source(:github) do |repo_name|
  repo_name = "#{repo_name}/#{repo_name}" unless repo_name.include?("/")
  "https://github.com/#{repo_name}.git"
end


# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem 'rails', "~> 5.2.7.1"

# restrictions due to CVEs
gem "rack", ">= 2.2.3.1"
gem "loofah", ">= 2.3.1"
gem "activerecord", ">= 5.2.4.5"
gem "activesupport", ">= 5.2.4.3"
gem "actionpack", ">= 5.2.4.3"
gem "activestorage", ">= 5.2.4.3"
gem "actionview", ">= 5.2.7.1"
gem "nokogiri", ">= 1.13.5"
gem "json", ">= 2.3.0"

gem "websocket-extensions", ">= 0.1.5"


# Use sqlite3 as the database for Active Record
gem 'sqlite3', "~> 1.3.6"

gem 'ecdsa',   :git => 'https://github.com/AnimaGUS-minerva/ruby_ecdsa.git', :branch => 'ecdsa_interface_openssl'

gem 'rspec-rails', '~> 3.6'

gem 'openssl', :path => "../minerva/ruby-openssl-upstreamed"
#gem 'openssl', :git => 'https://github.com/CIRALabs/ruby-openssl.git', :branch => 'ies-cms-dtls'
gem 'chariwt', :path => '../chariwt'
#gem 'chariwt', :git => 'https://github.com/AnimaGUS-minerva/ChariWTs.git', :branch => 'v0.8.0'

gem 'jwt'

gem 'celluloid', "~> 0.17.0"
#gem 'celluloid-io', :path => '../minerva/celluloid-io'
gem 'celluloid-io', :git => 'https://github.com/AnimaGUS-minerva/celluloid-io.git', :submodules => true, :branch => '0.17-dtls'

# Use Puma as the app server
#gem 'puma', '~> 3.0'

#gem 'coap', :path => '../minerva/coap'
gem 'coap', :git => 'https://github.com/AnimaGUS-minerva/coap.git', :branch => 'dtls-client', :ref => '8c130f19169d62c0783f18ddfd6d1a6c7b7a2180'
gem 'cbor'
gem 'cbor-diag'

# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem 'jbuilder', '~> 2.5'

# IP address management for use in ANIMA ACP
gem 'ipaddress'

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

