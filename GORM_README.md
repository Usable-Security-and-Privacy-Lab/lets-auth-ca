# GORM Implementation Documentation
This package uses the GORM database manager for go. There are a couple parts to this implementation, the models and the connection.

## The Models
### `/models/models.go`
The file containing all of the models are in the separate package models. There are currently 2 models that are contained in this file. The User object has a one to many relationship with credentials representing how a single user may register multiple FIDO2 tokens for their account. Each of these objects has the gorm.Model object embedded in the object. This enables gorm to add the columns to the table of ID, CreatedAt, UpdatedAt, and DeletedAt needed for gorm to properly interface with the database tables. Additionally in this package is the gorm hook function "BeforeCreate" which runs whenever a user is about to be inserted into the database. This function adds the display name field in case it wasn't given. Other operations can be added to this function in the future.

## The Connection 
### `/database/db.go`
This file implements the singleton pattern for the database connection through a wrapper around the gorm database connection. This wrapper is necessary in order to have the member functions contained in `/database/user.go` and other similar files to have access to the database connection without replicating that connection. The singleton pattern is implemented using go's `sync.Once` functionality and the connection instance is retrieved using the exported function `GetDB()`. 