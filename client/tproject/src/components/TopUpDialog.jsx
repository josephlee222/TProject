import { useState } from 'react'
import { Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText, Button, TextField, Stack, Box, InputAdornment } from '@mui/material'
import { LoadingButton } from '@mui/lab'
import * as yup from 'yup'
import { useFormik } from 'formik'
import { loadStripe } from "@stripe/stripe-js/pure";
import { Elements } from "@stripe/react-stripe-js"
import { useSnackbar } from 'notistack'
import http from '../http'
import { useNavigate } from 'react-router-dom'
import CloseIcon from '@mui/icons-material/Close';
import AddIcon from '@mui/icons-material/Add';
import PaymentForm from './PaymentForm'

const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLIC_KEY);

function TopUpDialog(props) {
    const [loading, setLoading] = useState(false);
    const [clientSecret, setClientSecret] = useState("");
    const [payment, setPayment] = useState(false);
    const { enqueueSnackbar } = useSnackbar();
    const topupFormik = useFormik(
        {
            initialValues: {
                amount: "",
            },
            validationSchema: yup.object({
                amount: yup.number().required("Amount is required").min(1, "Amount must be greater than 0").max(1000, "Cannot top-up above S$1000").typeError("Amount must be a number"),
            }),
            onSubmit: (data) => {
                setLoading(true);
                data.amount = data.amount.trim();
                data.amount = parseFloat(data.amount).toFixed(2)
                http.post("/payment/topup", data).then((res) => {
                    if (res.status === 200) {
                        setClientSecret(res.data.clientSecret);
                        setLoading(false);
                        setPayment(true);
                    }
                }).catch((err) => {
                    enqueueSnackbar("Top-up failed! " + err.response.data.message, { variant: "error" });
                })
            }
        }
    )

    const handleClose = () => {
        props.onClose();
        setPayment(false);
    }

    const appearance = {
        theme: "stripe",
        variables: {
            colorPrimary: '#0f6d51',
            colorBackground: '#ffffff',
            colorText: '#30313d',
            colorDanger: '#df1b41',
            fontFamily: 'Poppins, Ideal Sans, system-ui, sans-serif',
            spacingUnit: '4px',
            borderRadius: '4px',
        },
    }

    // Stripe element options with poppins font
    const elementOptions = { 
        clientSecret: clientSecret,
        fonts: [
            {
                cssSrc: 'https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap',
            },
        ],
        appearance: appearance,
     };


    return (
        <>
            <Dialog maxWidth={"sm"} fullWidth open={props.open} onClose={handleClose}>
                <DialogTitle>Top-up Wallet</DialogTitle>
                {!payment &&
                    <Box component="form" onSubmit={topupFormik.handleSubmit}>
                        <DialogContent sx={{ paddingTop: 0 }}>
                            <DialogContentText>
                                Enter the amount you want to top-up your wallet with.
                            </DialogContentText>
                            <TextField
                                autoFocus
                                margin="dense"
                                id="amount"
                                label="Amount to top-up"
                                type="amount"
                                name="amount"
                                fullWidth
                                variant="standard"
                                value={topupFormik.values.amount}
                                onChange={topupFormik.handleChange}
                                error={topupFormik.touched.amount && Boolean(topupFormik.errors.amount)}
                                helperText={topupFormik.touched.amount && topupFormik.errors.amount}
                                InputProps={{
                                    startAdornment: <InputAdornment position="start">S$</InputAdornment>,
                                }}
                            />
                        </DialogContent>
                        <DialogActions>
                            <Button onClick={handleClose} startIcon={<CloseIcon />}>Cancel</Button>
                            <LoadingButton type="submit" loadingPosition="start" loading={loading} variant="text" color="primary" startIcon={<AddIcon />}>Add Funds</LoadingButton>
                        </DialogActions>
                    </Box>
                }
                {payment &&
                    <Elements options={elementOptions} stripe={stripePromise}>
                        <PaymentForm onClose={handleClose} clientSecret={clientSecret} />
                    </Elements>
                }
            </Dialog>
        </>
    )
}

export default TopUpDialog