import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import InvoiceService from '../../src/services/invoiceService';
import db from '../../src/db';
import { Invoice } from '../../src/types/invoice';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>


describe('AuthService.generateJwt', () => {
  beforeEach (() => {
    jest.resetModules();
  });

  beforeAll(() => {
  });

  afterAll(() => {
  });

  it('listInvoices', async () => {
    const userId = 'user123';
    const state = 'paid';
    const operator = '=';
    const mockInvoices: Invoice[] = [
      { id: 'inv1', userId, amount: 100, dueDate: new Date(), status: 'paid' },
      { id: 'inv2', userId, amount: 200, dueDate: new Date(), status: 'paid' }
    ];
    // mock the database chain
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);

    const invoices = await InvoiceService.list(userId, state, operator);

    expect(selectChain.where).toHaveBeenCalledWith({ userId });
    expect(selectChain.where).toHaveBeenCalledWith('status', operator, state);
    expect(selectChain.select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });

  it('listInvoices no state', async () => {
    const userId = 'user123';
    const mockInvoices: Invoice[] = [
      { id: 'inv1', userId, amount: 100, dueDate: new Date(), status: 'paid' },
      { id: 'inv2', userId, amount: 200, dueDate: new Date(), status: 'unpaid' }
    ];
    // mock the database chain
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);
    const invoices = await InvoiceService.list(userId);

    expect(selectChain.where).toHaveBeenCalledWith({ userId });
    expect(selectChain.where).toHaveBeenCalledTimes(1); // Only called once (for userId)
    expect(selectChain.select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });

});
