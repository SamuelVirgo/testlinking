import React from 'react';
import ReactDOM from 'react-dom';
import { createStore, applyMiddleware } from 'redux'
import createSagaMiddleware from 'redux-saga'
import { Provider } from 'react-redux';
import thunk from 'redux-thunk';import Home from './pages/Home';

import reducer from './redux/reducer.js';
import mainSaga from './sagas/saga.js';
import myMiddleware from './redux/middleware.js';

const sagaMiddleware = createSagaMiddleware();
const store = createStore(reducer, applyMiddleware(myMiddleware, sagaMiddleware, thunk));
sagaMiddleware.run(mainSaga);

ReactDOM.render(
  <Provider store={store}><Home />
  </Provider>, document.getElementById('root')
);