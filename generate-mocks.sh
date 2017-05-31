#!/usr/bin/env bash
mockery -name UserStorage
mockery -name ClientStorage
mockery -name Client
mockery -name AuthorizeCodeStorage
mockery -name AccessTokenStorage
mockery -name RefreshTokenStorage
mockery -name TokenStrategy
mockery -name Request
mockery -name AuthorizeRequest
mockery -name AccessTokenRequest
mockery -name Session
