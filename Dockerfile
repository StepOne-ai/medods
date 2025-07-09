# Use an official Go image as the base
FROM golang:alpine

# Set the working directory to /app
WORKDIR /app

# Copy the Go source code into the container
COPY . /app

# Install any dependencies required by your app
RUN go get -d -v ./...

# Build your Go app
RUN go build -o main main.go

# Expose the port that your app will listen on
EXPOSE 8080

# Run your app when the container starts
CMD ["./main"]