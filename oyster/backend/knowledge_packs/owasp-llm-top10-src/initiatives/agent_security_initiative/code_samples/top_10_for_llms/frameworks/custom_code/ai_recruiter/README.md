<!-- source: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/99f4395589bdbd120ae961f9cd179e79d7f9b27f/initiatives/agent_security_initiative/code_samples/top_10_for_llms/frameworks/custom_code/ai_recruiter/README.md -->
# AI Recruiter Agent

## Overview

This agent ranks candidates based on the PDFs in resume_collection/

## Get Started

Set the environment variables in `.env` as needed.

```bash
$ cp .env.example .env
```

### Run All-in-One Command
```
$ cp .env.example .env
$ docker-compose build && docker-compose
 run resume_generator && docker-compose run ai_recruiter
```

### Run Commands Separately
If you'd prefer to run the services step-by-step for more control:

1. Build the Docker images:
   ```bash
   $ docker-compose build
   ```

2. Run the `resume_generator` to create resumes:
   ```bash
   $ docker-compose run resume_generator
   ```

3. Run the `ai_recruiter` service to evaluate candidates:
   ```bash
   $ docker-compose run ai_recruiter
   ```