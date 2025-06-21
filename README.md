# Chirpy

A lightweight Twitter-like social media application built with Go. I created Chirpy with the help of resources from Boot.dev as a learning project to explore web development and API design.

**Note:** This runs on localhost and is designed for educational purposes, not large-scale deployment.

## Features

Chirpy provides core social media functionality in a simplified package:

- **User Authentication**: Create profiles with API key validation to ensure secure chirp creation
- **Chirp Management**: Post short messages ("chirps") that are automatically linked to your profile
- **Content Filtering**: Filter chirps by author and sort by creation date
- **Premium Features**: Chirpy Red subscription allows post-editing capabilities

## Installation

1. Make sure you have Go installed on your system
2. Clone or install the project:
   ```bash
   go get github.com/jdingus93/chirpy
3. Navigate to the project directory and run:
    `go run main.go`

## Usage

Once it's running, you can:
  - Create a user profile
  - Post chirps to share updates
  - Browse and filter chirps by different users
  - Upgrade to Chirpy Red for additional features
