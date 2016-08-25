#!/usr/bin/ruby
require 'sinatra'
require 'mongo'
require 'haml'
require 'json'
require 'digest'

client = Mongo::Client.new('mongodb://127.0.0.1:27017/sinatra')
db = client.database
collection = client[:users]

status_codes = {
	s401:{
		status: 401,
		message: "unauthorized, please login"
	},
	nouser:{
		status: 401,
		message: "user not found"
	},
	session_error:{
		status: 401,
		message: "session not found"
	},
	session_expired:{
		status: 401,
		message: "session expired"
	}
}

before do
	return if(request.path_info == "/login")

	halt 401, status_codes[:s401].to_json.to_s if(params["session_key"] == nil)
	
	r = collection.find({"sessionKey" => session[:session_key]})
	halt 401, status_codes[:session_error].to_json.to_s if(r.count == 0)

	exTime = Time.parse(r.first["expireTime"])
	left = exTime-Time.now
	halt 401, status_codes[:session_error].to_json.to_s if(left <=0)
end

get "/" do
	"#{session[:session_key]}"
end

post "/login" do
	#lookup credentials in the database
	r = collection.find({"name" => params[:user], "password" => params[:pass]})
	puts r.count
	puts "NOGGGGGGGGER!!!"
	#generate sessionkey
	
	if(r.count == 1)
		session_key = Digest::SHA256.hexdigest(r.first["salt"]+Time.now.to_s).to_s
		collection.update_one({"name" => params[:user]},{"$set" => {"sessionKey" => session_key,"expireTime" => (Time.now + 24*60*60).to_s}})
		session_key
	else
		halt 401, status_codes[:nouser].to_json.to_s
	end
end