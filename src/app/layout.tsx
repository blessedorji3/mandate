import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MANDATE — Intelligence with boundaries",
  description: "Independent authorization and security for autonomous AI financial agents."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
