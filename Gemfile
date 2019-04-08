source 'https://rubygems.org'

git_source(:github) do |repo_name|
  repo_name = "#{repo_name}/#{repo_name}" unless repo_name.include?("/")
  "https://github.com/#{repo_name}.git"
end


# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem 'rails', '~> 5.0.4'

# restrictions due to CVEs
gem "rack", ">= 2.0.6"
gem "loofah", ">= 2.2.3"

# Use sqlite3 as the database for Active Record
gem 'sqlite3', "~> 1.3.6"

gem 'rspec-rails', '~> 3.6'

gem 'openssl', :path => '../minerva/ruby-openssl'
gem 'chariwt', :path => '../chariwt'
#gem 'chariwt', :git => 'https://github.com/mcr/ChariWTs.git'

gem 'ecdsa',   :git => 'https://github.com/AnimaGUS-minerva/ruby_ecdsa.git', :branch => 'ecdsa_interface_openssl'
gem 'jwt'

#gem 'celluloid-io', :path => '../minerva/celluloid-io'
gem 'celluloid-io', :git => 'git@github.com:AnimaGUS-minerva/celluloid-io.git', :submodules => true

# Use Puma as the app server
#gem 'puma', '~> 3.0'

gem 'coap', :path => '../minerva/coap'
#gem 'coap', :git => 'git@github.com:AnimaGUS-minerva/coap.git', :branch => 'dtls-client'
gem 'cbor'
gem 'cbor-diag'

# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem 'jbuilder', '~> 2.5'

# Use Capistrano for deployment
# gem 'capistrano-rails', group: :development

# for decoding MIME content types.
gem 'mail'


gem 'byebug'

group :development do
  # Spring speeds up development by keeping your application running in the background. Read more: https://github.com/rails/spring
  gem 'spring'
  gem 'spring-watcher-listen', '~> 2.0.0'

  gem 'sprockets', "~> 3.7.2"
end

