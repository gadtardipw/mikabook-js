const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { UserInputError } = require('apollo-server');

const { validateRegisterInput, validateLoginInput }  = require('../../util/validators');
const { SECRET_KEY } = require('../../config'); // SECRET KEY
const User = require("../../models/User");

//res is response/result
//most testing done on graphql playground

function generateToken(user){ // jwt token generator
    return jwt.sign(
    {
    id: user.id,
    email: user.email,
    username: user.username
    }, 
    SECRET_KEY,
    {expiresIn: '1h'}
    );

}

module.exports = {
    Mutation: { // GRAPHQL: queries to fetch data, mutations to modify server-side data
        async login(_, { username, password }){ // login
            const {errors, valid} = validateLoginInput(username, password );

            if(!valid){
                throw new UserInputError('LoginErrors1', {errors});
            }

            const user = await User.findOne({ username }); // find user in database

            if(!user){
                errors.general = 'user not found';
                throw new UserInputError('User not found', {errors});
            }


            const match = await bcrypt.compare(password, user.password); // comparing passwords
            if(!match){
                errors.general = 'Wrong credentials';
                throw new UserInputError('Wrong credentials', {errors});
            }

            const token = generateToken(user);

            return {
                ...user._doc,
                id: user._id,
                token
            };
        },

        async register( // new user regist
            _,
            {
             registerInput : { username, email, password, confirmPassword }
            }
          ) {
            const { valid, errors } = validateRegisterInput(
                username, 
                email, 
                password, 
                confirmPassword
                );
            if (!valid) {
                throw new UserInputError('Errors', { errors });
            }
            const user = await User.findOne({ username });
            if (user){
                throw new UserInputError('Username is taken', {
                    errors: {
                        username: 'This username is taken'
             }
            });
            }

            password = await bcrypt.hash(password, 12); // password encryption

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            });

            const res = await newUser.save();

            const token = generateToken(res)

            return {
                ...res._doc,
                id: res._id,
                token
            };
        }
    },

}; 