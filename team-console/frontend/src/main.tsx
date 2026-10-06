import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App as AntApp, ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import './styles.css';
import { uiTheme } from './uiTheme';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ConfigProvider locale={zhCN} theme={uiTheme}>
      <AntApp><App /></AntApp>
    </ConfigProvider>
  </StrictMode>,
);
