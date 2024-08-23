import React, { useState, useEffect } from 'react'
import { styled } from '@mui/material/styles'
import { useParams } from 'react-router'
import PropTypes from 'prop-types'
import ArrowForwardIosSharpIcon from '@mui/icons-material/ArrowForwardIosSharp'
import MuiAccordion from '@mui/material/Accordion'
import MuiAccordionSummary from '@mui/material/AccordionSummary'
import MuiAccordionDetails from '@mui/material/AccordionDetails'
import Typography from '@mui/material/Typography'

const ReadMore = ({ id, text, amountOfWords = 36 }) => {
  const [isExpanded, setIsExpanded] = useState(false)
  const splittedText = text.split(' ')
  const itCanOverflow = splittedText.length > amountOfWords
  const beginText = itCanOverflow
    ? splittedText.slice(0, amountOfWords - 1).join(' ')
    : text
  const endText = splittedText.slice(amountOfWords - 1).join(' ')
  
  const handleKeyboard = (e) => {
    if (e.code === 'Space' || e.code === 'Enter') {
      setIsExpanded(!isExpanded)
    }
  }

  return (
    <span id={id}>
      {beginText}
      {itCanOverflow && (
        <>
          {!isExpanded && <span>... </span>}
          <span 
            className={`${!isExpanded && 'hidden'}`} 
            aria-hidden={!isExpanded}
          >
            {endText}
          </span>
          <span
            className='text-violet-400 ml-2'
            role="button"
            tabIndex={0}
            aria-expanded={isExpanded}
            aria-controls={id}
            onKeyDown={handleKeyboard}
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? 'show less' : 'show more'}
          </span>
        </>
      )}
    </span>
  )
}

ReadMore.propTypes = {
  id: PropTypes.string,
  text: PropTypes.string,
  amountOfWords: PropTypes.number
}

const Accordion = styled((props) => (
  <MuiAccordion disableGutters elevation={0} square {...props} />
))(({ theme }) => ({
  border: `1px solid ${theme.palette.divider}`,
  '&:not(:last-child)': {
    borderBottom: 0,
  },
  '&::before': {
    display: 'none',
  },
}));

const AccordionSummary = styled((props) => (
  <MuiAccordionSummary
    expandIcon={<ArrowForwardIosSharpIcon sx={{ fontSize: '0.9rem' }} />}
    {...props}
  />
))(({ theme }) => ({
  backgroundColor:
    theme.palette.mode === 'dark'
      ? 'rgba(255, 255, 255, .05)'
      : 'rgba(0, 0, 0, .03)',
  flexDirection: 'row-reverse',
  '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
    transform: 'rotate(90deg)',
  },
  '& .MuiAccordionSummary-content': {
    marginLeft: theme.spacing(1),
  },
}));

const AccordionDetails = styled(MuiAccordionDetails)(({ theme }) => ({
  padding: theme.spacing(2),
  borderTop: '1px solid rgba(0, 0, 0, .125)',
}));


const ShowVEXPage = () => {
  const params = useParams()
  const [vex, set_vex] = useState([])
  const [statements, set_statments] = useState([])
  const [expanded, setExpanded] = useState('');

  const handleChange = (panel) => (event, newExpanded) => {
    setExpanded(newExpanded ? panel : false);
  };

  useEffect(() => {
    const access_token = localStorage.getItem('access_token')
    fetch('http://localhost:8000/vex/show/' + params.id, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${access_token}`
      }
    })
      .then((r) => r.json())
      .then((r) => {
        set_vex(r)
        set_statments(r.vex.statements)
      })
  }, [params.id])

  return (
    <div className='flex flex-col h-screen justify-center items-center m-auto w-8/12'>
      <p className='mb-6 text-lg font-normal text-gray-500 lg:text-xl sm:px-16 xl:px-48 dark:text-gray-400 text-center'>
        {vex.owner}/{vex.name}: {vex.sbom_path}
      </p>
      {statements.map((statement, index) => (
        <Accordion className='w-full' key={index} expanded={expanded === 'panel'+index} onChange={handleChange('panel'+index)}>
          <AccordionSummary aria-controls="panel1d-content" id="panel1d-header">
            <Typography>Statement {index}</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography>
              <span>- Vulnerability:<br /></span>
              <span>&ensp;&ensp;&ensp;{'\u2022'} @id: {statement.vulnerability["@id"]}<br /></span>
              <span>&ensp;&ensp;&ensp;{'\u2022'} name: {statement.vulnerability.name}<br /></span> 
              <span>&ensp;&ensp;&ensp;{'\u2022'} description: <ReadMore id="read-more-text" text={statement.vulnerability.description} /><br /></span>
              <span>- Timestamp: {statement.timestamp}<br /></span>
              <span>- Last Updated: {statement.last_updated}<br /></span>
              <span>- Status: {statement.status}<br /></span>
              <span>- Justification: {statement.justification}<br /></span>
              <span>- Supplier: {statement.supplier}</span>
            </Typography>
          </AccordionDetails>
        </Accordion>
      ))}
    </div>
  )
}

export { ShowVEXPage }
