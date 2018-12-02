const { Helper } = require('casbin');
const { Enforcer } = require('casbin')
const jwt = require('jsonwebtoken');

const CasbinJWTAdapter = function(decodedToken) {
  this.decodedToken = decodedToken
  
  this.loadPolicy = function(model) {

    if (!this.decodedToken) {
      throw new Error('invalid Token. Token must be provided');
    } 

    const lines = decodedToken.policy.split('\n');
    lines.forEach(n => {
      const line = n.trim();

      if (!line) {
        return;
      }

      Helper.loadPolicyLine(line, model);
    });
  }

  this.savePolicy = function() {
    throw new Error("Transient adapter; cannot save")
  }

  this.addPolicy = function() {
    throw new Error("Transient adapter; cannot add")
  }

  this.removePolicy = function() {
    throw new Error("Transient adapter; cannot remove")
  }

  this.removeFilteredPolicy = function() {
    throw new Error("Transient adapter; cannot remove")
  }
}

module.exports = function(modelSource, jwtSecret, ignoredPathsRegex) {
  return async (req, res, next) => {
  
    if (ignoredPathsRegex) {
      if (typeof(ignoredPathsRegex === "string")) {
        if (req.originalUrl.match(new RegExp(ignoredPathsRegex, "g"))) {
          return next()
        }
      }else{
        if (req.originalUrl.match(ignoredPathsRegex)) {
          return next()
        }
      }
    }
    
    let token = null
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
      token = req.query.token;
    }
  
    let model = null
    if (typeof(modelSource) === "string") { //model from file
      model = Enforcer.newModel(modelSource, '');
      
    }else{ //object model
      model = Enforcer.newModel(modelSource.fromText)      
      
    }
    
    jwt.verify(token, jwtSecret, async(err, decoded) => {
      if (err) {
        console.error(err)
        return res.status(401).send({ auth: false, message: 'Unauthorized access.' });
      } 
      
      const enforcer = await Enforcer.newEnforcer(model, new CasbinJWTAdapter(decoded))
      const { originalUrl: path, method } = req
      const username = token ? decoded.sub  : 'anonymous'
      
      if(enforcer.enforce(username, path, method)) {
        next()
      }else{
        return res.status(403).send({ auth: false, message: 'Unauthorized access.' });
      }
    })
  }
} 