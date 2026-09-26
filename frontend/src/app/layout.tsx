import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PortBiter - AI Security Scanner",
  description: "AI-powered security scanning with PortBiter",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
