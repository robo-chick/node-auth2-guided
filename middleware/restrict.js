const jwt = require("jsonwebtoken")

function restrict(role) {	
	// use a scale for checking user roles since admin users
	// should still have access to basic user endpoints,
	// but basic users shouldn't have access to admin endpoints.
	const roles = [
		"basic",
		"admin",
		"super_admin"
	]


	return async (req, res, next) => {
		const authError = {
			message: "Invalid credentials",
		}

		try {
			// token is coming from the client's cookie jar, in the "cookie" header
			const token = req.cookies.token
			if (!token) {
				return res.status(401).json(authError)
			}

			// decode the token, re-sign the payload, and check if signature is valid
			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
				if (err) {
					return res.status(401).json(authError)
				}

				// check if the role in our token is above or equal to the required role for the endpoint
				if (role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
					return res.status(403).json({
						message: "You are not allowed here",
					})
				}
				// we know the user is authorized at this point
				// make the token's payload available to other midleware functions
				req.token = decoded

				next()
			})
		} catch(err) {
			next(err)
		}
	}
}

module.exports = restrict