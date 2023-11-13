package org.opensearch.security.tools.democonfig;

/**
 * Enum for demo certificates
 */
public enum DemoCertificate {
    ADMIN_CERT(
        "kirk.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIEmDCCA4CgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iYwDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkyMDA2MzdaFw0zMzA4MjYyMDA2MzdaME0xCzAJBgNVBAYT\n"
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ8wDQYDVQQKDAZjbGllbnQxDzANBgNVBAsMBmNs\n"
            + "aWVudDENMAsGA1UEAwwEa2lyazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
            + "ggEBAJVcOAQlCiuB9emCljROAXnlsPbG7PE3kNz2sN+BbGuw686Wgyl3uToVHvVs\n"
            + "paMmLUqm1KYz9wMSWTIBZgpJ9hYaIbGxD4RBb7qTAJ8Q4ddCV2f7T4lxao/6ixI+\n"
            + "O0l/BG9E3mRGo/r0w+jtTQ3aR2p6eoxaOYbVyEMYtFI4QZTkcgGIPGxm05y8xonx\n"
            + "vV5pbSW9L7qAVDzQC8EYGQMMI4ccu0NcHKWtmTYJA/wDPE2JwhngHwbcIbc4cDz6\n"
            + "cG0S3FmgiKGuuSqUy35v/k3y7zMHQSdx7DSR2tzhH/bBL/9qGvpT71KKrxPtaxS0\n"
            + "bAqPcEkKWDo7IMlGGW7LaAWfGg8CAwEAAaOCASswggEnMAwGA1UdEwEB/wQCMAAw\n"
            + "DgYDVR0PAQH/BAQDAgXgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMIHPBgNVHSME\n"
            + "gccwgcSAFBeH36Ba62YSp9XQ+LoSRTy3KwCcoYGVpIGSMIGPMRMwEQYKCZImiZPy\n"
            + "LGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQRXhh\n"
            + "bXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290IENB\n"
            + "MSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0GCFHfkrz782p+T9k0G\n"
            + "xGeM4+BrehWKMB0GA1UdDgQWBBSjMS8tgguX/V7KSGLoGg7K6XMzIDANBgkqhkiG\n"
            + "9w0BAQsFAAOCAQEANMwD1JYlwAh82yG1gU3WSdh/tb6gqaSzZK7R6I0L7slaXN9m\n"
            + "y2ErUljpTyaHrdiBFmPhU/2Kj2r+fIUXtXdDXzizx/JdmueT0nG9hOixLqzfoC9p\n"
            + "fAhZxM62RgtyZoaczQN82k1/geMSwRpEndFe3OH7arkS/HSbIFxQhAIy229eWe5d\n"
            + "1bUzP59iu7f3r567I4ob8Vy7PP+Ov35p7Vv4oDHHwgsdRzX6pvL6mmwVrQ3BfVec\n"
            + "h9Dqprr+ukYmjho76g6k5cQuRaB6MxqldzUg+2E7IHQP8MCF+co51uZq2nl33mtp\n"
            + "RGr6JbdHXc96zsLTL3saJQ8AWEfu1gbTVrwyRA==\n"
            + "-----END CERTIFICATE-----"
    ),
    ADMIN_CERT_KEY(
        "kirk-key.pem",
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVXDgEJQorgfXp\n"
            + "gpY0TgF55bD2xuzxN5Dc9rDfgWxrsOvOloMpd7k6FR71bKWjJi1KptSmM/cDElky\n"
            + "AWYKSfYWGiGxsQ+EQW+6kwCfEOHXQldn+0+JcWqP+osSPjtJfwRvRN5kRqP69MPo\n"
            + "7U0N2kdqenqMWjmG1chDGLRSOEGU5HIBiDxsZtOcvMaJ8b1eaW0lvS+6gFQ80AvB\n"
            + "GBkDDCOHHLtDXBylrZk2CQP8AzxNicIZ4B8G3CG3OHA8+nBtEtxZoIihrrkqlMt+\n"
            + "b/5N8u8zB0Encew0kdrc4R/2wS//ahr6U+9Siq8T7WsUtGwKj3BJClg6OyDJRhlu\n"
            + "y2gFnxoPAgMBAAECggEAP5TOycDkx+megAWVoHV2fmgvgZXkBrlzQwUG/VZQi7V4\n"
            + "ZGzBMBVltdqI38wc5MtbK3TCgHANnnKgor9iq02Z4wXDwytPIiti/ycV9CDRKvv0\n"
            + "TnD2hllQFjN/IUh5n4thHWbRTxmdM7cfcNgX3aZGkYbLBVVhOMtn4VwyYu/Mxy8j\n"
            + "xClZT2xKOHkxqwmWPmdDTbAeZIbSv7RkIGfrKuQyUGUaWhrPslvYzFkYZ0umaDgQ\n"
            + "OAthZew5Bz3OfUGOMPLH61SVPuJZh9zN1hTWOvT65WFWfsPd2yStI+WD/5PU1Doo\n"
            + "1RyeHJO7s3ug8JPbtNJmaJwHe9nXBb/HXFdqb976yQKBgQDNYhpu+MYSYupaYqjs\n"
            + "9YFmHQNKpNZqgZ4ceRFZ6cMJoqpI5dpEMqToFH7tpor72Lturct2U9nc2WR0HeEs\n"
            + "/6tiptyMPTFEiMFb1opQlXF2ae7LeJllntDGN0Q6vxKnQV+7VMcXA0Y8F7tvGDy3\n"
            + "qJu5lfvB1mNM2I6y/eMxjBuQhwKBgQC6K41DXMFro0UnoO879pOQYMydCErJRmjG\n"
            + "/tZSy3Wj4KA/QJsDSViwGfvdPuHZRaG9WtxdL6kn0w1exM9Rb0bBKl36lvi7o7xv\n"
            + "M+Lw9eyXMkww8/F5d7YYH77gIhGo+RITkKI3+5BxeBaUnrGvmHrpmpgRXWmINqr0\n"
            + "0jsnN3u0OQKBgCf45vIgItSjQb8zonLz2SpZjTFy4XQ7I92gxnq8X0Q5z3B+o7tQ\n"
            + "K/4rNwTju/sGFHyXAJlX+nfcK4vZ4OBUJjP+C8CTjEotX4yTNbo3S6zjMyGQqDI5\n"
            + "9aIOUY4pb+TzeUFJX7If5gR+DfGyQubvvtcg1K3GHu9u2l8FwLj87sRzAoGAflQF\n"
            + "RHuRiG+/AngTPnZAhc0Zq0kwLkpH2Rid6IrFZhGLy8AUL/O6aa0IGoaMDLpSWUJp\n"
            + "nBY2S57MSM11/MVslrEgGmYNnI4r1K25xlaqV6K6ztEJv6n69327MS4NG8L/gCU5\n"
            + "3pEm38hkUi8pVYU7in7rx4TCkrq94OkzWJYurAkCgYATQCL/rJLQAlJIGulp8s6h\n"
            + "mQGwy8vIqMjAdHGLrCS35sVYBXG13knS52LJHvbVee39AbD5/LlWvjJGlQMzCLrw\n"
            + "F7oILW5kXxhb8S73GWcuMbuQMFVHFONbZAZgn+C9FW4l7XyRdkrbR1MRZ2km8YMs\n"
            + "/AHmo368d4PSNRMMzLHw8Q==\n"
            + "-----END PRIVATE KEY-----"
    ),
    NODE_CERT(
        "esnode.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIEPDCCAySgAwIBAgIUZjrlDPP8azRDPZchA/XEsx0X2iIwDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkwNDIzMTJaFw0zMzA4MjYwNDIzMTJaMFcxCzAJBgNVBAYT\n"
            + "AmRlMQ0wCwYDVQQHDAR0ZXN0MQ0wCwYDVQQKDARub2RlMQ0wCwYDVQQLDARub2Rl\n"
            + "MRswGQYDVQQDDBJub2RlLTAuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA\n"
            + "A4IBDwAwggEKAoIBAQCm93kXteDQHMAvbUPNPW5pyRHKDD42XGWSgq0k1D29C/Ud\n"
            + "yL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0\n"
            + "HGkn47XVu3EwbfrTENg3jFu+Oem6a/501SzITzJWtS0cn2dIFOBimTVpT/4Zv5qr\n"
            + "XA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8n\n"
            + "dibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b6l+KLo3IKpfTbAIJXIO+M67FLtWKtttD\n"
            + "ao94B069skzKk6FPgW/OZh6PRCD0oxOavV+ld2SjAgMBAAGjgcYwgcMwRwYDVR0R\n"
            + "BEAwPogFKgMEBQWCEm5vZGUtMC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hxAAAAAA\n"
            + "AAAAAAAAAAAAAAABhwR/AAABMAsGA1UdDwQEAwIF4DAdBgNVHSUEFjAUBggrBgEF\n"
            + "BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU0/qDQaY10jIo\n"
            + "wCjLUpz/HfQXyt8wHwYDVR0jBBgwFoAUF4ffoFrrZhKn1dD4uhJFPLcrAJwwDQYJ\n"
            + "KoZIhvcNAQELBQADggEBAD2hkndVih6TWxoe/oOW0i2Bq7ScNO/n7/yHWL04HJmR\n"
            + "MaHv/Xjc8zLFLgHuHaRvC02ikWIJyQf5xJt0Oqu2GVbqXH9PBGKuEP2kCsRRyU27\n"
            + "zTclAzfQhqmKBTYQ/3lJ3GhRQvXIdYTe+t4aq78TCawp1nSN+vdH/1geG6QjMn5N\n"
            + "1FU8tovDd4x8Ib/0dv8RJx+n9gytI8n/giIaDCEbfLLpe4EkV5e5UNpOnRgJjjuy\n"
            + "vtZutc81TQnzBtkS9XuulovDE0qI+jQrKkKu8xgGLhgH0zxnPkKtUg2I3Aq6zl1L\n"
            + "zYkEOUF8Y25J6WeY88Yfnc0iigI+Pnz5NK8R9GL7TYo=\n"
            + "-----END CERTIFICATE-----"
    ),
    NODE_KEY(
        "esnode-key.pem",
        "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCm93kXteDQHMAv\n"
            + "bUPNPW5pyRHKDD42XGWSgq0k1D29C/UdyL21HLzTJa49ZU2ldIkSKs9JqbkHdyK0\n"
            + "o8MO6L8dotLoYbxDWbJFW8bp1w6tDTU0HGkn47XVu3EwbfrTENg3jFu+Oem6a/50\n"
            + "1SzITzJWtS0cn2dIFOBimTVpT/4Zv5qrXA6Cp4biOmoTYWhi/qQl8d0IaADiqoZ1\n"
            + "MvZbZ6x76qTrRAbg+UWkpTEXoH1xTc8ndibR7+HP6OTqCKvo1NhE8uP4pY+fWd6b\n"
            + "6l+KLo3IKpfTbAIJXIO+M67FLtWKtttDao94B069skzKk6FPgW/OZh6PRCD0oxOa\n"
            + "vV+ld2SjAgMBAAECggEAQK1+uAOZeaSZggW2jQut+MaN4JHLi61RH2cFgU3COLgo\n"
            + "FIiNjFn8f2KKU3gpkt1It8PjlmprpYut4wHI7r6UQfuv7ZrmncRiPWHm9PB82+ZQ\n"
            + "5MXYqj4YUxoQJ62Cyz4sM6BobZDrjG6HHGTzuwiKvHHkbsEE9jQ4E5m7yfbVvM0O\n"
            + "zvwrSOM1tkZihKSTpR0j2+taji914tjBssbn12TMZQL5ItGnhR3luY8mEwT9MNkZ\n"
            + "xg0VcREoAH+pu9FE0vPUgLVzhJ3be7qZTTSRqv08bmW+y1plu80GbppePcgYhEow\n"
            + "dlW4l6XPJaHVSn1lSFHE6QAx6sqiAnBz0NoTPIaLyQKBgQDZqDOlhCRciMRicSXn\n"
            + "7yid9rhEmdMkySJHTVFOidFWwlBcp0fGxxn8UNSBcXdSy7GLlUtH41W9PWl8tp9U\n"
            + "hQiiXORxOJ7ZcB80uNKXF01hpPj2DpFPWyHFxpDkWiTAYpZl68rOlYujxZUjJIej\n"
            + "VvcykBC2BlEOG9uZv2kxcqLyJwKBgQDEYULTxaTuLIa17wU3nAhaainKB3vHxw9B\n"
            + "Ksy5p3ND43UNEKkQm7K/WENx0q47TA1mKD9i+BhaLod98mu0YZ+BCUNgWKcBHK8c\n"
            + "uXpauvM/pLhFLXZ2jvEJVpFY3J79FSRK8bwE9RgKfVKMMgEk4zOyZowS8WScOqiy\n"
            + "hnQn1vKTJQKBgElhYuAnl9a2qXcC7KOwRsJS3rcKIVxijzL4xzOyVShp5IwIPbOv\n"
            + "hnxBiBOH/JGmaNpFYBcBdvORE9JfA4KMQ2fx53agfzWRjoPI1/7mdUk5RFI4gRb/\n"
            + "A3jZRBoopgFSe6ArCbnyQxzYzToG48/Wzwp19ZxYrtUR4UyJct6f5n27AoGBAJDh\n"
            + "KIpQQDOvCdtjcbfrF4aM2DPCfaGPzENJriwxy6oEPzDaX8Bu/dqI5Ykt43i/zQrX\n"
            + "GpyLaHvv4+oZVTiI5UIvcVO9U8hQPyiz9f7F+fu0LHZs6f7hyhYXlbe3XFxeop3f\n"
            + "5dTKdWgXuTTRF2L9dABkA2deS9mutRKwezWBMQk5AoGBALPtX0FrT1zIosibmlud\n"
            + "tu49A/0KZu4PBjrFMYTSEWGNJez3Fb2VsJwylVl6HivwbP61FhlYfyksCzQQFU71\n"
            + "+x7Nmybp7PmpEBECr3deoZKQ/acNHn0iwb0It+YqV5+TquQebqgwK6WCLsMuiYKT\n"
            + "bg/ch9Rhxbq22yrVgWHh6epp\n"
            + "-----END PRIVATE KEY-----"
    ),
    ROOT_CA(
        "root-ca.pem",
        "-----BEGIN CERTIFICATE-----\n"
            + "MIIExjCCA66gAwIBAgIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcNAQEL\n"
            + "BQAwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt\n"
            + "cGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYDVQQLDBhFeGFtcGxl\n"
            + "IENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUgQ29tIEluYy4gUm9v\n"
            + "dCBDQTAeFw0yMzA4MjkwNDIwMDNaFw0yMzA5MjgwNDIwMDNaMIGPMRMwEQYKCZIm\n"
            + "iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEZMBcGA1UECgwQ\n"
            + "RXhhbXBsZSBDb20gSW5jLjEhMB8GA1UECwwYRXhhbXBsZSBDb20gSW5jLiBSb290\n"
            + "IENBMSEwHwYDVQQDDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0EwggEiMA0GCSqG\n"
            + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEPyN7J9VGPyJcQmCBl5TGwfSzvVdWwoQU\n"
            + "j9aEsdfFJ6pBCDQSsj8Lv4RqL0dZra7h7SpZLLX/YZcnjikrYC+rP5OwsI9xEE/4\n"
            + "U98CsTBPhIMgqFK6SzNE5494BsAk4cL72dOOc8tX19oDS/PvBULbNkthQ0aAF1dg\n"
            + "vbrHvu7hq7LisB5ZRGHVE1k/AbCs2PaaKkn2jCw/b+U0Ml9qPuuEgz2mAqJDGYoA\n"
            + "WSR4YXrOcrmPuRqbws464YZbJW898/0Pn/U300ed+4YHiNYLLJp51AMkR4YEw969\n"
            + "VRPbWIvLrd0PQBooC/eLrL6rvud/GpYhdQEUx8qcNCKd4bz3OaQ5AgMBAAGjggEW\n"
            + "MIIBEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU\n"
            + "F4ffoFrrZhKn1dD4uhJFPLcrAJwwgc8GA1UdIwSBxzCBxIAUF4ffoFrrZhKn1dD4\n"
            + "uhJFPLcrAJyhgZWkgZIwgY8xEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ\n"
            + "k/IsZAEZFgdleGFtcGxlMRkwFwYDVQQKDBBFeGFtcGxlIENvbSBJbmMuMSEwHwYD\n"
            + "VQQLDBhFeGFtcGxlIENvbSBJbmMuIFJvb3QgQ0ExITAfBgNVBAMMGEV4YW1wbGUg\n"
            + "Q29tIEluYy4gUm9vdCBDQYIUd+SvPvzan5P2TQbEZ4zj4Gt6FYowDQYJKoZIhvcN\n"
            + "AQELBQADggEBAIopqco/k9RSjouTeKP4z0EVUxdD4qnNh1GLSRqyAVe0aChyKF5f\n"
            + "qt1Bd1XCY8D16RgekkKGHDpJhGCpel+vtIoXPBxUaGQNYxmJCf5OzLMODlcrZk5i\n"
            + "jHIcv/FMeK02NBcz/WQ3mbWHVwXLhmwqa2zBsF4FmPCJAbFLchLhkAv1HJifHbnD\n"
            + "jQzlKyl5jxam/wtjWxSm0iyso0z2TgyzY+MESqjEqB1hZkCFzD1xtUOCxbXgtKae\n"
            + "dgfHVFuovr3fNLV3GvQk0s9okDwDUcqV7DSH61e5bUMfE84o3of8YA7+HUoPV5Du\n"
            + "8sTOKRf7ncGXdDRA8aofW268pTCuIu3+g/Y=\n"
            + "-----END CERTIFICATE-----"
    );

    private final String fileName;
    private final String content;

    DemoCertificate(String fileName, String content) {
        this.fileName = fileName;
        this.content = content;
    }

    public String getFileName() {
        return fileName;
    }

    public String getContent() {
        return content;
    }
}
