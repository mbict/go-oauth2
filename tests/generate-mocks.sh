#!/usr/bin/env bash

mockery -dir "../" -name UserStorage
mockery -dir "../" -name ClientStorage
mockery -dir "../" -name Client
mockery -dir "../" -name AuthorizeCodeStorage
mockery -dir "../" -name AccessTokenStorage
mockery -dir "../" -name RefreshTokenStorage
mockery -dir "../" -name TokenStrategy
mockery -dir "../" -name Request
mockery -dir "../" -name AuthorizeRequest
mockery -dir "../" -name AccessTokenRequest
mockery -dir "../" -name Session
