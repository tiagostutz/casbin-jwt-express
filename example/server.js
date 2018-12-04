import express from 'express'
import casbinJWTExpress from 'casbin-jwt-express'

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

var token = jwt.sign({ 
    sub: "helena",
    policy: "p, helena, /brinquedo/*, GET"
})
console.log("PUT THIS TOKEN ON AUTHORIZATION HEADER:\n", token)

const app = express();
app.use(casbinJWTExpress(casbinPolicyModel, jwtSecret, "/"))


app.get('/', (req, res, next) => {
    res.send(`This endpoint is opened. Won't check permission and leave anyone access it.`)
    next()
});  
app.get('/brinquedo/*', (req, res, next) => {
    res.send(`If you see this message you provided an valid token and have access`)
    next()
});  

app.listen(7000);
console.log(`Server started on ${port}`)