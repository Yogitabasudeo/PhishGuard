import { RouterProvider } from "react-router";
import { ThemeProvider } from "./context/ThemeContext";
import { router } from "./routes";
import { AuthProvider } from "./context/AuthContext";
import { NotificationProvider } from "./context/NotificationContext";
import { ScanProvider } from "./context/ScanContext";
function App() {
  return <ThemeProvider>
    <AuthProvider>
      <NotificationProvider>
        <ScanProvider>
          <RouterProvider router={router} />
        </ScanProvider>
      </NotificationProvider>
    </AuthProvider>
  </ThemeProvider>;
}
export {
  App as default
};
