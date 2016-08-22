#!/usr/bin/ruby
require 'sinatra'
require 'mongo'
require 'haml'
require 'digest'

enable :sessions
set :session_secret, 'superduperSaveWord123!!!ß'
client = Mongo::Client.new('mongodb://127.0.0.1:27017/sinatra')
db = client.database
collection = client[:users]

before do
	puts request.path_info
	if(request.path_info != "/login")
		if(session[:session_key] == false)
			session[:cause] = "first"
			puts "NO SESSION KEY"
			redirect "/login"
			return
		end
		r = collection.find({"sessionKey" => session[:session_key]})
		if(r.count == 0)
			puts "NO USER WITH THIS SESSION FOUND"
			session[:cause] = "first"
			session[:session_key] = false
			redirect "/login"
			return
		end
		exTime = Time.parse(r.first["expireTime"])
		left = exTime-Time.now
		if(left <=0)
			puts "SESSION EXPIRED"
			session[:cause] = "expired"
			session[:session_key] = false
			redirect "/login"
			return
		end
	end
end

get "/" do
	"#{session[:session_key]}"
end

get "/login" do 
	puts session[:cause]
	haml :index, :locals => {:cause => session[:cause]}
end

post "/login" do
	#lookup credentials in the database
	r = collection.find({"name" => params[:user], "password" => params[:pass]})
	#generate sessionkey
	if(r.count == 1)
		session_key = Digest::SHA256.hexdigest(r.first["salt"]+Time.now.to_s).to_s
		collection.update_one({"name" => params[:user]},{"$set" => {"sessionKey" => session_key,"expireTime" => (Time.now + 24*60*60).to_s}})
		session[:session_key] = session_key
		redirect "/"
	else
		session[:cause] = "nouser"
		redirect "/login"
	end
end