// Copyright 2016 Arne Johanson
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

try {
	process.chdir(__dirname);
}
catch(err) {
	console.log("Could not change working directory to app root");
	process.exit(1);
}

const express = require("express");
const crypto = require("crypto");

const userDB = require("./user_db");

const appPort = 3332;
const localAddr = "localhost";
const tokenLifeSpan = 2 * 60 * 60 * 1000; // in [ms]
const clearTokenInterval = 15 * 1000; // in [ms]

const acceptAllHosts = process.argv.includes("--acceptAllHosts");



var tokenDB = {};
// key: token
// value: {
//	userID: ID
//	timeout: timestamp when token expires
//}

function removeTimedOutTokens() {
	const now = new Date().getTime();
	Object.keys(tokenDB).forEach(function(t) {
		if(tokenDB[t].timeout <= now) {
			delete tokenDB[t];
		}
	});
}
setInterval(removeTimedOutTokens, clearTokenInterval);


const app = express();

app.delete("/token/:token", function (req, res) {
	if(!tokenDB.hasOwnProperty(req.params.token)) {
		res.status(404).send("Token not found");
		return;
	}
	delete tokenDB[req.params.token];
	res.send("OK");
});

app.get("/token", function (req, res) {
	if(!req.query.hasOwnProperty("userName") || !req.query.hasOwnProperty("password")) {
		res.status(400).send("Missing user name or password");
		return;
	}
	if(!userDB.hasOwnProperty(req.query.userName) || userDB[req.query.userName].password !== req.query.password) {
		res.status(403).send("Invalid credentials");
		return;
	}
	
	const token = crypto.randomBytes(48).toString("hex");
	if(tokenDB.hasOwnProperty(token)) {
		res.status(500).send("Server error");
		return;
	}
	tokenDB[token] = {
		userID: userDB[req.query.userName].userID,
		timeout: (new Date().getTime() + tokenLifeSpan)
	};
	res.json({token: token});
});

app.get("/userid", function (req, res) {
	if(!req.query.hasOwnProperty("token")
		|| !tokenDB.hasOwnProperty(req.query.token)
		|| tokenDB[req.query.token].timeout <= new Date().getTime()) {
		res.status(404).send("Invalid token");
		return;
	}
	tokenDB[req.query.token].timeout = new Date().getTime() + tokenLifeSpan;
	res.json({userID : tokenDB[req.query.token].userID});
});

console.log("acceptAllHosts:" + acceptAllHosts);
app.listen(appPort, acceptAllHosts ? null : localAddr, function () {
	console.log("Auth app listening on port " + appPort);
});
