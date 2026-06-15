import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Campus Portal",
  description: "Risk-Adaptive Zero Trust Access Control prototype",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
