# express-mongoDB

<h3> Data sanitization against NoSQL query injection - npm i express-mongo-sanitize</h3>
<pre>
If it not exists let you login and get access to any account(with the password parameter) using the password 
the attacker put in the get req to see this:
cancel this line,open postman on login req and enter in the body:
{
"email":{"$gt":""}, 
"password": "pass1234"
}
</pre>
