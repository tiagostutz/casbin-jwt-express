const express = require('express') 
const casbinJWTExpress = require('casbin-jwt-express') 

const jwt = require('jsonwebtoken');
const jwtSecret = "secret-example-of-casbin-jwt-express"

const casbinPolicyModel = { fromText:  `
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
    `
}

const app = express();

app.use(casbinJWTExpress(casbinPolicyModel, jwtSecret, "/opened"))

app.get('/opened', (req, res, next) => {
    res.send(`Success! This endpoint is opened. Won't check permission and leave anyone access it.`)
    next()
});  
app.get('/brinquedo/*', (req, res, next) => {
    res.send(`Success! If you see this message you provided an valid token and have access`)
    next()
});  

const port = 7007
app.listen(port);
console.log(`Server started on ${port}`)


var token = jwt.sign({ 
    sub: "helena",
    policy: "p, helena, /brinquedo/break, GET"
}, jwtSecret)

console.log("PUT THIS TOKEN ON AUTHORIZATION HEADER:\n\n", token, "\n\n")
console.log("Requests examples.")

console.log('ALLOWED :');
console.log('\n');
console.log(`curl -X GET http://localhost:7007/opened`);
console.log('\n');
console.log(`curl -X GET http://localhost:7007/brinquedo/break  -H 'Authorization: Bearer ${token}'`);
console.log('\n');
console.log('DENIED:');
console.log('\n');
console.log(`curl -X GET http://localhost:7007/brinquedo/buy  -H 'Authorization: Bearer ${token}'`);
console.log('\n');


