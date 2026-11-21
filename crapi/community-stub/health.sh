#!/bin/sh
nc -z localhost "${SERVER_PORT:-8087}"
