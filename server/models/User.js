const bcrypt = require("bcrypt");

module.exports = (sequelize, DataTypes) => {
    // Account Types:
    // 0 - Admin
    // 1 - General User
    // 2 - Approved Driver User
    // 3 - Unapproved Driver User

    const User = sequelize.define("User", {
        email: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        name: {
            type: DataTypes.STRING,
            allowNull: false
        },
        password: {
            type: DataTypes.STRING,
            allowNull: true,
            set(value) {
                // Hash the password before saving it to the database
                this.setDataValue("password", bcrypt.hashSync(value, 10));
            }
        },
        profile_picture: {
            type: DataTypes.STRING,
            allowNull: true
        },
        profile_picture_type: {
            type: DataTypes.STRING,
            allowNull: true
        },
        account_type: {
            type: DataTypes.TINYINT,
            allowNull: false,
            defaultValue: 1
        },
        phone_number: {
            type: DataTypes.STRING,
            allowNull: true
        },
        cash: {
            type: DataTypes.DECIMAL(10, 2),
            allowNull: false,
            defaultValue: 0.00
        },
        points: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        is_active: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: true
        },
        is_2fa_enabled: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false
        },
        is_google_auth_enabled: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        is_fb_auth_enabled: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        is_email_verified: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false
        },
        driver_application_sent: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false
        },
        accepted_routes: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        completed_routes: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        aborted_routes: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        driven_distance: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        total_earned: {
            type: DataTypes.DOUBLE,
            allowNull: false,
            defaultValue: 0.0
        },
        current_route: {
            type: DataTypes.JSON,
            allowNull: false,
            defaultValue: 0
        },
        rideDirections: {
            type: DataTypes.TEXT('long') ,
            allowNull: true,
        },
        on_duty: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false
        },
        delivery_address: {
            type: DataTypes.STRING,
            allowNull: true
        },
        bike_pass_expiry: {
            type: DataTypes.DATE,
            allowNull: true
        },
    }, {
        indexes: [{ unique: true, fields: ["email"] }]
    });

    User.associate = (models) => {
        User.hasMany(models.Transaction, {
            foreignKey: "user_id",
            onDelete: "CASCADE",
        });

        User.hasOne(models.Secret, {
            foreignKey: "user_id",
            onDelete: "CASCADE",
        });

        User.hasMany(models.RideRequest, {
            foreignKey: "userId",
            onDelete: "CASCADE",
        });

        User.hasMany(models.Ticket, {
            foreignKey: "user_id",
            onDelete: "CASCADE",
        });

        User.hasMany(models.Message, {
            foreignKey: "user_id",
            onDelete: "CASCADE",
        });

        User.hasMany(models.Article, {
            foreignKey: "user_id",
            onDelete: "CASCADE",
        });

        User.hasMany(models.RideRating, {
            foreignKey: "userId",
            onDelete: "CASCADE",
        });
    };
    return User;
}