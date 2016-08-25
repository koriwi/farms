#!/usr/bin/ruby
require 'sinatra'
require 'mongo'
require 'yaml'
require 'json'
require 'digest'
require 'logger'

#init mongo
client = Mongo::Client.new('mongodb://127.0.0.1:27017/farms')
db = client.database
collection = client[:users]

#load config file
config = YAML::load_file("./cfg/config.yaml")

#setup logging
logger = Logger.new(config["logging"]["logfile"])
logger.formatter = proc do |severity, datetime, progname, msg|
   "#{datetime}:#{severity}: #{msg}\n"
end

logger.info "Server Started"

#status codes
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
	},
	user_exists:{
		status: 401,
		message: "username already exists"
	},
	bad: {
		status: 400,
		message: "bad request"
	},
	reg_succ: {
		status: 201,
		message: "user registered"
	}
}

before do
	return if(request.path_info == "/login")
	return if(request.path_info == "/register")

	halt 401, status_codes[:s401].to_json.to_s if(params["session_key"] == nil)
	
	r = collection.find({"session_key" => params["session_key"]})
	halt 401, status_codes[:session_error].to_json.to_s if(r.count == 0)

	exTime = Time.parse(r.first["expiry_time"])
	left = exTime-Time.now
	halt 401, status_codes[:session_error].to_json.to_s if(left <=0)
end

post "/login" do
	#lookup credentials in the database
	salted_pw = Digest::SHA256.hexdigest(params["password"]+config["security"]["salt"]).to_s
	r = collection.find({"username" => params["username"], "password" => salted_pw})

	halt 401, status_codes[:nouser].to_json.to_s if(r.count == 0)

	#generate sessionkey	
	session_key = Digest::SHA256.hexdigest(config["security"]["salt"]+Time.now.to_s).to_s
	collection.update_one({"username" => params["username"]},{"$set" => {"session_key" => session_key,"expiry_time" => (Time.now + 24*60*60).to_s}})
	session_key
end

post "/register" do
	
	begin
		#check if password and username length is long enough
		halt 400, status_codes[:bad].to_json.to_s if(params["username"].to_s.length < config["register"]["username"].to_i)
		halt 400, status_codes[:bad].to_json.to_s if(params["password"].to_s.length < config["register"]["password"].to_i)

		r = collection.find({"username" => params["username"]})
		halt 401, status_codes[:user_exists].to_json.to_s if(r.count > 0)

		salted_pw = Digest::SHA256.hexdigest(params["password"]+config["security"]["salt"]).to_s
		collection.insert_one({
			"username" => params["username"],
			"password" => salted_pw,
			"session_key" => "",
			"expiry_time" => ""
		})
		status_codes[:reg_succ].to_json.to_s
	rescue
		logger.warn "register broke!"
		halt 400, status_codes[:bad].to_json.to_s
	end

end