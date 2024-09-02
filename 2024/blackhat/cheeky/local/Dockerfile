# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /cheeky

# Copy the current directory contents into the container at /app
COPY . /cheeky

# Install necessary Python packages
RUN pip install pycryptodome

# Define the environment variable for the flag
ENV DYN_FLAG=BHFlagY{506f6c79-6d65726f-57617348-65726521}

# Make port 80 available to the world outside this container
EXPOSE 9999

# Run the script when the container launches
CMD ["python3", "chall.py"]
