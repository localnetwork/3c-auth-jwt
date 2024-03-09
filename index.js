const mysql = require('mysql2')
const bcrypt = require('bcrypt')
var jwt = require('jsonwebtoken');
const saltRounds = 10; 

const express = require('express')
const port = 3000;
const app = express();

app.use(express.json());
app.listen(port, () => {
    console.log(`http://localhost:${port}`)
})

const connection = mysql.

createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: '3c-g1'
})

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']; 
    

    
    if(!token) {
        res.json({
            error: "Token not provided."
        })
    }

    const bearerToken = token.split(' ')[1];
    

    jwt.verify(bearerToken, 'sample_secret', (err, decoded) => {
        if(err) {
            console.log(err)
            return res.json({
                error: "Invalid token"
            })
        } 
        req.user =decoded;
        next(); 

    })

}

connection.connect((error) => {
    if(error) {
    console.log(error)
        console.log('Cannot connect') 
    }else {
        console.log('Successfully connected')
    }
})
 
app.post('/register', async (req, res) => {
    const { username, password } = req.body 
    const hashedPassword = await bcrypt.hash('password', saltRounds);
    console.log(hashedPassword); 

    connection.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (error, results) => {
        if(error) {
            console.log(error); 
            res.json({
                message: 'Server error'
            })
        }else {
            if(results.affectedRows > 0) {
                res.json({
                    message: 'User successfully created.'
                })
            }else {
                res.json({
                    message: 'Failed to create the user.'
                })

            }
        }
        connection.end(); 
    })
})

app.post('/login', (req, res) => {
    const { username, password } = req.body 
    connection.query("SELECT * FROM users WHERE username = ?", [username], async (error, results) => {
        if (error) {
            console.log('Error retrieving user.')
            return res.json({
                message: "Server error"
            })
        }
    
        if (results.length === 0) {
            return res.json({
                error: "Invalid credentials."
            })
        }
    
        const user = results[0];
    
        const passwordMatch = await bcrypt.compare(password, user.password);
    
        if (!passwordMatch) {
            return res.json({
                error: "Invalid credentials."
            })
        }
    
        const token = jwt.sign({
            userId: user.id,
            username: user.username
        }, 'sample_secret');
        
        res.json({ token });
    });
})

app.get('/dashboard', verifyToken, (req, res) => {
    res.json({
        message: "This is a protected api!!!"
    })
})
