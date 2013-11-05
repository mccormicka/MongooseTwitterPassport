'use strict';

exports = module.exports = function Consumer(schema, pluginOptions) {

    var extension;
    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);

    if (!pluginOptions || !pluginOptions.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }
    if (!pluginOptions.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }
    if (!pluginOptions.twitterConsumerKey) {
        throw log.error('You must provide a twitterKey in order to use MongooseTwitter ');
    }
    if (!pluginOptions.twitterConsumerSecret) {
        throw log.error('You must provide a twitterSecret in order to use MongooseTwitter ');
    }
    if (!pluginOptions.twitterCallbackURL) {
        throw log.error('You must provide a twitterCallbackURL in order to use MongooseTwitter ');
    }

    var _ = require('lodash');
    var strategy;
    var Strategy = require('passport-twitter').Strategy;
    var passport = pluginOptions.passport;
    var consumerKey = pluginOptions.twitterConsumerKey;
    var consumerSecret = pluginOptions.twitterConsumerSecret;
    var callbackURL = pluginOptions.twitterCallbackURL;
    var skipExtendedUserProfile = _.isUndefined(pluginOptions.twitterSkipExtendedUserProfile) ?
        true : pluginOptions.twitterSkipExtendedUserProfile;

    var TYPE = pluginOptions.tableName.toLowerCase();
    var upperTableName = pluginOptions.tableName.slice(0, 1).toUpperCase() + pluginOptions.tableName.slice(1);
    var lowerTableName = pluginOptions.tableName.slice(0, 1).toLowerCase() + pluginOptions.tableName.slice(1);
    var CREATE_METHOD = 'create' + upperTableName;
    var FIND_METHOD = 'find' + upperTableName;
    var REMOVE_METHOD = 'remove' + upperTableName;
    var FIND_BY_METHOD = 'findBy' + upperTableName;

    /**
     * Ensure plugin is initialized when connected to mongoose.
     */
    schema.on('init', function(model){
        log.info(upperTableName, ' Initialized');
        getExtension(model.db);
    });

    addSchemaExtensions();

    schema.statics.twitterAuth = function (req, res, next) {
        this.useTwitterStrategy();
        passport.authenticate('twitter', function (err, user, twitter) {
            if (!user) {
                var message = 'Twitter Error: user denied access';
                log.error(message, err);
                return next(message);
            }
            req.twitter = twitter;
            next(err);

        })(req, res, next);
    };

    /**
     * Tell Passport to use the Strategy.
     */
    schema.statics.useTwitterStrategy = function () {
        if (!strategy) {
            var Model = this;
            passport.use('twitter', new Strategy({
                    consumerKey: consumerKey,
                    consumerSecret: consumerSecret,
                    callbackURL: callbackURL,
                    passReqToCallback: true,
                    skipExtendedUserProfile: skipExtendedUserProfile
                },
                function (req, token, tokenSecret, params, profile, done) {
                    var options = {
                        profile: profile,
                        token: token,
                        tokenSecret: tokenSecret
                    };

                    if (req.user) {
                        handleLoggedInUser(Model, req.user, options, done);
                    } else {
                        handlNotLoggedInUser(Model, req, options, done);
                    }
                }
            ));
            strategy = true;
        }
    };

    function handleLoggedInUser(Model, user, options, done) {
        var profile = options.profile;

        log.debug('TwitterExtension:User already logged in');
        //Already Logged In either associate account or update
        Model[upperTableName]().findOne({'profile.id': profile.id}, function (err, twitter) {
            //No Associated Twitter Account so create one.
            if (err || !twitter) {
                log.debug('No Associated Twitter Account trying to create one');
                return createTwitterAssociation(user, options, done);
            } else {
                if(twitter.modelId !== user._id.toString()){
//                    //TODO:User is trying to associate two accounts with the same twitter account!
//                    //ask to merge accounts? Automatically merge accounts? need to decide.
//                    //In a future release
                    log.warn('User is trying to associate two accounts! TODO: Handle this correctly');
                }
                //Already have an associated Twitter Account update its tokens.
                log.debug('Already Associated Twitter Account trying to update');
                return updateTwitterAssociation(twitter, user, options, done);
            }
        });
    }

    function handlNotLoggedInUser(Model, req, options, done) {
        var profile = options.profile;

        log.debug('TwitterExtension:User NOT logged in trying to find account', profile.id);
        Model[upperTableName]().findOne({'profile.id': profile.id}, function (err, twitter) {
            if (err || !twitter) {
                createNewUser(Model, done, req, options);
            } else {
                findAndUpdateTwitterAssociation(Model, twitter, done, req, options);
            }
        });
    }

    function createTwitterAssociation(user, options, done) {
        var token = options.token;
        var tokenSecret = options.tokenSecret;
        var profile = options.profile;
        profile.snapshotDate = Date.now();
        user[CREATE_METHOD]({token: token, secret: tokenSecret, profile: profile, profiles:[profile]},
            function (err, result) {
                log.debug('Create result ', err, result);
                if (err) {
                    log.error('Error Attaching Twitter Account', err);
                    return done(err);
                }
                done(err, user, result);
            });
    }

    function updateTwitterAssociation(twitter, user, options, done) {
        log.debug('Updating Twitter Association');
        var token = options.token;
        var tokenSecret = options.tokenSecret;
        var profile = options.profile;
        profile.snapshotDate = Date.now();
        twitter.update({
            toke: token,
            secret: tokenSecret,
            profiles: {$push:profile},
            profile:profile,
            modelId:user._id

        }, function (err) {
            if (err) {
                log.error('Error updating Twitter Association', err);
                return done(err);
            }
            return done(err, user);
        });
    }

    function createNewUser(Model, done, req, options) {
        log.debug('Creating new user');
        Model.create({}, function (err, user) {
            if (err || !user) {
                var message = 'Unable to create user';
                log.warn(message, err, user);
                return done(message);
            }
            req.login(user, function (err) {
                if (err) {
                    log.error(err);
                    return done(err);
                } else {
                    return createTwitterAssociation(user, options, done);
                }
            });
        });
    }

    function findAndUpdateTwitterAssociation(Model, twitter, done, req, options) {
        Model.findOne({_id: twitter.modelId}, function (err, user) {
            if (err || !user) {
                var message = 'Unable to associate twitter account with user';
                log.error(message, err);
                return done(message);
            }
            req.login(user, function (err) {
                if (err) {
                    log.error(err);
                    return done(err);
                } else {
                    return updateTwitterAssociation(twitter, user, options, done);
                }
            });
        });
    }

    /**
     * Here is the magic. We pass the db instance from the associated methods
     * and if there is no extension type created we create a temporary mongoose
     * schema in order to build a valid Mongoose object without ever having
     * to import mongoose. This is required as if we import mongoose and the
     * user of the library imports mongoose they are not the same instance
     * and as such Mongoose.Schema === Mongoose.Schema is false which breaks
     * mongoose.
     * @private
     * @param db
     * @returns {*}
     */
    function getExtension(db) {
        if (!extension) {
            //Create temporary model so we can get a hold of a valid Schema object.
            var extensionSchema = db.model('____' + TYPE + '____', {}).schema;
            extensionSchema.statics.TYPE = TYPE;

            var extensionOptions = {
                type: {type: String, 'default': TYPE},
                modelId: String,
                token: String,
                secret: String,
                profiles:[{}],
                profile:{}
            };

            extensionSchema.add(extensionOptions);
            //If a schema was passed in then add it to our extension.
            if (pluginOptions.schema) {
                extensionSchema.add(pluginOptions.schema);
            }

            extensionSchema.methods.findModel = function (Model, next) {
                Model.findOne({_id: this.modelId}, next);
            };

            extensionSchema.statics.createExtension = function (model, options, next) {
                if (_.isFunction(options)) {
                    next = options;
                    options = {};
                }
                options.modelId = model._id;
                log.debug('Creating ' + pluginOptions.tableName);
                this.create(options, function (err, result) {
                    if (err) {
                        log.error(err);
                    }
                    log.debug(result);
                    next(err, result);
                });
            };

            extensionSchema.statics.removeExtension = function (model, options, next) {
                if (_.isFunction(options)) {
                    next = options;
                    options = {};
                }
                options.modelId = model._id;
                this.remove(options, function (err, result) {
                    log.debug('Removing' + pluginOptions.tableName);
                    if (err) {
                        log.error(err);
                    }
                    log.debug(result);
                    next(err, result);
                });

            };

            extension = db.model(TYPE, extensionSchema);
        }
        return extension;
    }

    function addSchemaExtensions() {
        if (typeof schema.methods[CREATE_METHOD] === 'function') {
            throw new Error('The tablename you specified is not unique to this schema', schema);
        }
        log.debug();
        log.debug('---------------- ' + TYPE.toUpperCase() + ' --- Methods ---');
        log.debug();
        /**
         * create an extension to associate with your model instance can be accessed by
         * yourModelInstance.create'extensionName'(options, next) (without quotes, case sensitive)
         * @param next (err, extension )
         */
        schema.methods[CREATE_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            getExtension(this.db).createExtension(this, options, next);
        };
        log.debug(TYPE + '.method.' + CREATE_METHOD);
        /**
         * create an extension to associate with your model instance can be accessed by
         * YourModel.create'extensionName'(modelInstance, options, next) (without quotes, case sensitive)
         * @param next (err, extension )
         */
        schema.statics[CREATE_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            getExtension(this.db).createExtension(this, options, next);
        };
        log.debug(TYPE + '.static.' + CREATE_METHOD);
        /**
         * Removes an extension associated with your model instance can be accessed by
         * yourModelInstance.remove'extensionName'(options, next) (without quotes, case sensitive)
         * @param next (err, extension )
         */
        schema.methods[REMOVE_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            getExtension(this.db).removeExtension(this, options, next);
        };
        log.debug(TYPE + '.method.' + REMOVE_METHOD);
        /**
         * Removes an extension associated with your model can be accessed by
         * YourModel.remove'extensionName'(model, options, next) (without quotes, case sensitive)
         * @param next (err, extension )
         */
        schema.statics[REMOVE_METHOD] = function (model, options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            getExtension(this.db).removeExtension(model, options, next);
        };
        log.debug(TYPE + '.static.' + REMOVE_METHOD);
        /**
         * Get extensions associated with your model instance can be accessed by
         * YourModelInstance.get'extensionName'(options, next) (without quotes, case sensitive)
         * @param next (err, extension )
         */
        schema.methods[FIND_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            options.modelId = this._id;
            getExtension(this.db).find(options, next);
        };
        log.debug(TYPE + '.method.' + FIND_METHOD);
        /**
         * Get an extension associated with your model instance can be accessed by
         * YourModel.get'extensionName'(modelInstance, options, next) (without quotes, case sensitive)
         * @param next (err, extension)
         */
        schema.statics[FIND_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            getExtension(this.db).find(options, next);
        };
        log.debug(TYPE + '.static.' + FIND_METHOD);
        /**
         * Find a YourModelInstance by the extension.
         * YourModel.findBy'extensionName'(options, next) (without quotes, case sensitive)
         * @param next (err, YourModelInstance )
         */
        schema.statics[FIND_BY_METHOD] = function (options, next) {
            if(_.isFunction(options)){
                next = options;
                options = {};
            }
            var self = this;
            getExtension(this.db).findOne(options, function (err, result) {
                result.findModel(self, next);
            });
        };
        log.debug(TYPE + '.static.' + FIND_BY_METHOD);
        /**
         * Returns the extension instance so that you can perform usual
         * mongoose methods on it.
         * @param next
         */
        schema.methods[lowerTableName] = function (next) {
            next(null, getExtension(this.db));
        };
        log.debug(TYPE + '.method.' + lowerTableName);
        /**
         * Returns the extension instance so that you can perform usual
         * mongoose methods on it.
         * @param next
         */
        schema.statics[lowerTableName] = function (next) {
            next(null, getExtension(this.db));
        };
        log.debug(TYPE + '.static.' + lowerTableName);
        /**
         * Call the extension directly without having to pass a callback.
         * @returns {*}
         */
        schema.methods[upperTableName] = function () {
            return getExtension(this.db);
        };
        log.debug(TYPE + '.methods.' + upperTableName);
        /**
         * Call the extension directly without having to pass a callback.
         * @returns {*}
         */
        schema.statics[upperTableName] = function () {
            return getExtension(this.db);
        };
        log.debug(TYPE + '.static.' + upperTableName);
    }
};