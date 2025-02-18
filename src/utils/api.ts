const checkEndpoint = async (url: string): Promise<boolean> => {
  try {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 2000) // 2 second timeout

    const response = await fetch(`${url}/health`, {
      method: "GET",
      signal: controller.signal,
    })

    clearTimeout(timeoutId)
    return response.ok
  } catch {
    return false
  }
}

export const getAPIURL = async (): Promise<string> => {
  const localURL = process.env.REACT_APP_API_LOCAL_URL || "http://localhost:5001"
  const ec2URL = process.env.REACT_APP_API_EC2_URL || "http://ec2-52-90-169-241.compute-1.amazonaws.com:5001"

  // Try local first
  if (await checkEndpoint(localURL)) {
    console.log("Using local API endpoint")
    return localURL
  }

  // Fallback to EC2
  if (await checkEndpoint(ec2URL)) {
    console.log("Using EC2 API endpoint")
    return ec2URL
  }

  // Default to local if both fail
  console.warn("Both endpoints failed, defaulting to local")
  return localURL
}
