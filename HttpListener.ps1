# HttpListener.ps1
# Simple HTTP listener to verify Wirespeed-Forwarder.ps1 message forwarding with pretty-printed JSON

param (
    [string]$Url = "http://localhost",  # Base URL for the listener (default: http://localhost)
    [int]$Port = 8080                   # Port to listen on (default: 8080)
)

# Construct the full listener prefix
$listenerPrefix = "$Url`:$Port/"
$listener = [System.Net.HttpListener]::new()

try {
    # Set up the listener
    $listener.Prefixes.Add($listenerPrefix)
    $listener.Start()
    Write-Host "Listening on $listenerPrefix..."

    # Main loop to handle incoming requests
    while ($true) {
        $context = $listener.GetContext()
        if ($context.Request.HttpMethod -eq "POST") {
            # Read the entire request body
            $reader = [System.IO.StreamReader]::new($context.Request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()

            # Pretty-print the JSON body
            try {
                $jsonObject = $body | ConvertFrom-Json
                $prettyJson = $jsonObject | ConvertTo-Json -Depth 10
                Write-Host "Received POST body (pretty-printed):"
                Write-Host $prettyJson
            }
            catch {
                Write-Host "Received POST body (raw, non-JSON): $body"
            }

            # Send a 200 OK response
            $response = $context.Response
            $response.StatusCode = 200
            $writer = [System.IO.StreamWriter]::new($response.OutputStream)
            $writer.Write("OK")
            $writer.Close()
            $response.Close()
        }
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}
finally {
    # Ensure the listener is stopped if an error occurs or script is interrupted
    if ($listener.IsListening) {
        $listener.Stop()
    }
    $listener.Close()
}