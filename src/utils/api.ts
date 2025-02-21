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
  // Debug logging
  console.log("All environment variables:", process.env)
  console.log("REACT_APP_API_EC2_URL value:", process.env.REACT_APP_API_EC2_URL)

  // Temporarily hardcode the new EC2 URL
  const ec2URL = "http://ec2-54-157-41-25.compute-1.amazonaws.com:5001"
  const localURL = process.env.REACT_APP_API_LOCAL_URL || "http://localhost:5001"

  console.log("Final EC2 URL after fallback:", ec2URL)
  console.log("Trying EC2 URL:", ec2URL)
  // Try EC2 first
  if (await checkEndpoint(ec2URL)) {
    console.log("Successfully connected to EC2")
    return ec2URL
  }
  console.log("EC2 connection failed")

  console.log("Trying local URL:", localURL)
  // Fallback to local
  if (await checkEndpoint(localURL)) {
    console.log("Successfully connected to local")
    return localURL
  }
  console.log("Local connection failed")

  // Default to EC2 if both fail
  console.warn("Both endpoints failed, defaulting to EC2:", ec2URL)
  return ec2URL
}
