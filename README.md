# Interoperability - Authorization Server

## Token Generation Errors
In case of error during the token generation, the response must contain only a generic message, and not the specific cause of the rejection.\
This approach mitigates external threats like Enumeration Attacks.\
Logs must always contain specific details of the error.